package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// ---- a small in-memory uci for the firewall config ----

type fakeSec struct {
	name string // "" for an anonymous section
	typ  string
	opts map[string][]string
	keys []string // option order
}

type fakeFW struct {
	secs    []*fakeSec
	reloads int
	failOn  string // an op kind+key that fails, to test rollbacks
	applied [][]executor.Op
}

// label is the name `uci show` prints for a section.
func (f *fakeFW) label(s *fakeSec) string {
	if s.name != "" {
		return s.name
	}
	n := 0
	for _, x := range f.secs {
		if x == s {
			break
		}
		if x.typ == s.typ {
			n++
		}
	}
	return fmt.Sprintf("@%s[%d]", s.typ, n)
}

func (f *fakeFW) find(label string) *fakeSec {
	for _, s := range f.secs {
		if f.label(s) == label {
			return s
		}
	}
	return nil
}

func (f *fakeFW) add(name, typ string, kv ...string) {
	s := &fakeSec{name: name, typ: typ, opts: map[string][]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		if _, ok := s.opts[kv[i]]; !ok {
			s.keys = append(s.keys, kv[i])
		}
		s.opts[kv[i]] = append(s.opts[kv[i]], kv[i+1])
	}
	f.secs = append(f.secs, s)
}

func (f *fakeFW) show() string {
	var b strings.Builder
	for _, s := range f.secs {
		l := f.label(s)
		fmt.Fprintf(&b, "firewall.%s=%s\n", l, s.typ)
		for _, k := range s.keys {
			var vals []string
			for _, v := range s.opts[k] {
				vals = append(vals, "'"+v+"'")
			}
			fmt.Fprintf(&b, "firewall.%s.%s=%s\n", l, k, strings.Join(vals, " "))
		}
	}
	return b.String()
}

func (f *fakeFW) clone() *fakeFW {
	c := &fakeFW{}
	for _, s := range f.secs {
		n := &fakeSec{name: s.name, typ: s.typ, opts: map[string][]string{}, keys: append([]string(nil), s.keys...)}
		for k, v := range s.opts {
			n.opts[k] = append([]string(nil), v...)
		}
		c.secs = append(c.secs, n)
	}
	return c
}

func (f *fakeFW) run(op executor.Op) error {
	if err := executor.Validate(op); err != nil {
		return err
	}
	if f.failOn != "" && strings.HasPrefix(op.Kind+" "+strings.Join(op.Args, " "), f.failOn) {
		return errors.New("injected failure")
	}
	key := func(k string) (sec, opt string) {
		k = strings.TrimPrefix(k, "firewall.")
		sec, opt, _ = strings.Cut(k, ".")
		return
	}
	switch op.Kind {
	case "uci_set":
		sec, opt := key(op.Args[0])
		if opt == "" {
			if f.find(sec) == nil {
				f.add(sec, op.Args[1])
			}
			return nil
		}
		s := f.find(sec)
		if s == nil {
			return fmt.Errorf("no section %s", sec)
		}
		if _, ok := s.opts[opt]; !ok {
			s.keys = append(s.keys, opt)
		}
		s.opts[opt] = []string{op.Args[1]}
	case "uci_add_list":
		sec, opt := key(op.Args[0])
		s := f.find(sec)
		if s == nil {
			return fmt.Errorf("no section %s", sec)
		}
		if _, ok := s.opts[opt]; !ok {
			s.keys = append(s.keys, opt)
		}
		s.opts[opt] = append(s.opts[opt], op.Args[1])
	case "uci_delete":
		sec, opt := key(op.Args[0])
		s := f.find(sec)
		if s == nil {
			return nil
		}
		if opt == "" {
			for i, x := range f.secs {
				if x == s {
					f.secs = append(f.secs[:i], f.secs[i+1:]...)
					break
				}
			}
			return nil
		}
		delete(s.opts, opt)
		for i, k := range s.keys {
			if k == opt {
				s.keys = append(s.keys[:i], s.keys[i+1:]...)
				break
			}
		}
	case "uci_rename":
		sec, _ := key(op.Args[0])
		s := f.find(sec)
		if s == nil {
			return fmt.Errorf("no section %s", sec)
		}
		s.name = op.Args[1]
	case "initd":
		if op.Args[0] == "firewall" {
			f.reloads++
		}
	}
	return nil
}

// installFakeFW points the allow list code at f, with a router whose
// Internet zone is "wan", whose LAN is 192.0.2.0/24, and a firewall that
// creates every set it is given and uses it.
func installFakeFW(t *testing.T, f *fakeFW) {
	t.Helper()
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "show" && args[1] == "firewall" {
			return []byte(f.show()), nil
		}
		if len(args) == 2 && args[0] == "changes" {
			return nil, nil
		}
		if len(args) == 3 && args[0] == "-q" && args[1] == "get" {
			k := args[2]
			if k == "network.wan" {
				return []byte("interface\n"), nil
			}
			if strings.HasPrefix(k, "firewall.") {
				sec, opt, _ := strings.Cut(strings.TrimPrefix(k, "firewall."), ".")
				if s := f.find(sec); s != nil {
					if opt == "" {
						return []byte(s.typ + "\n"), nil
					}
					if v, ok := s.opts[opt]; ok {
						return []byte(strings.Join(v, " ") + "\n"), nil
					}
				}
			}
			return nil, errors.New("not found")
		}
		return nil, errors.New("unexpected uci call")
	})
	InvalidatePrefix("")

	var snap *fakeFW
	oldSnap, oldRestore, oldApply, oldRun := allowSnapshotFn, allowRestoreFn, allowApplyFn, allowRunFn
	oldList, oldRuleset, oldNft, oldGw, oldSup := allowNftListFn, allowRulesetFn, allowNftFn, allowGatewayFn, allowSupported
	oldSubnets, oldStore, oldRun2, oldLookup := clientSubnetsFn, allowStorePath, allowRunDir, allowLookupFn
	t.Cleanup(func() {
		allowSnapshotFn, allowRestoreFn, allowApplyFn, allowRunFn = oldSnap, oldRestore, oldApply, oldRun
		allowNftListFn, allowRulesetFn, allowNftFn, allowGatewayFn, allowSupported = oldList, oldRuleset, oldNft, oldGw, oldSup
		clientSubnetsFn, allowStorePath, allowRunDir, allowLookupFn = oldSubnets, oldStore, oldRun2, oldLookup
		allowResetForTest()
	})
	allowResetForTest()
	dir := t.TempDir()
	allowStorePath = filepath.Join(dir, "allowlists.json")
	allowRunDir = filepath.Join(dir, "run")
	allowSupported = func() bool { return true }
	allowGatewayFn = func() bool { return true }
	clientSubnetsFn = func() []ubus.Subnet {
		return []ubus.Subnet{{Interface: "lan", Device: "br-lan", Address: "192.0.2.1", Mask: 24}}
	}
	allowLookupFn = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	allowSnapshotFn = func(string) (string, error) { snap = f.clone(); return "snap", nil }
	allowRestoreFn = func(string, string) error {
		if snap != nil {
			f.secs = snap.secs
		}
		return nil
	}
	allowApplyFn = func(ops []executor.Op, _ []executor.Op) error {
		f.applied = append(f.applied, ops)
		for _, op := range ops {
			if err := f.run(op); err != nil {
				return err
			}
		}
		return nil
	}
	allowRunFn = f.run
	// The running firewall: every set of the config exists and every rule
	// using one shows up.
	allowNftListFn = func(set string) (string, error) {
		for _, s := range f.secs {
			if s.typ == "ipset" && len(s.opts["name"]) > 0 && s.opts["name"][0] == set {
				return "set " + set + " {\n}\n", nil
			}
		}
		return "", errors.New("No such file or directory")
	}
	// fw4's rendering: each enabled rule using a set, named in its comment.
	allowRulesetFn = func() (string, error) {
		var b strings.Builder
		for _, s := range f.secs {
			if v := s.opts["ipset"]; len(v) > 0 && !(len(s.opts["enabled"]) > 0 && s.opts["enabled"][0] == "0") {
				name := ""
				if n := s.opts["name"]; len(n) > 0 {
					name = n[0]
				}
				set, _ := ipsetRef(v[0])
				fmt.Fprintf(&b, "\t\tip saddr @%s counter accept comment \"!fw4: %s\"\n", set, name)
			}
		}
		return b.String(), nil
	}
	allowNftFn = func(string) error { return nil }
}

func allowResetForTest() {
	allowMu.Lock()
	allowLoaded = false
	allowData = allowStore{}
	allowHosts = map[string]*allowHost{}
	allowApplied = map[string]string{}
	allowMu.Unlock()
}

// baseFW is a router: a LAN and a WAN zone, a forward limited to a set
// something else fills, a VPN port open to anyone (an anonymous rule, as
// LuCI makes them) and NetGrip's remote SSH rule.
func baseFW() *fakeFW {
	f := &fakeFW{}
	f.add("", "zone", "name", "lan", "network", "lan")
	f.add("", "zone", "name", "wan", "network", "wan", "network", "wan6")
	f.add("", "ipset", "name", "web_allowed", "match", "src_ip")
	f.add("", "redirect", "name", "Web", "src", "wan", "src_dport", "443", "dest", "lan",
		"dest_ip", "192.0.2.10", "dest_port", "443", "proto", "tcp", "target", "DNAT", "ipset", "web_allowed")
	f.add("", "rule", "name", "VPN-in", "src", "wan", "proto", "udp", "dest_port", "51820", "target", "ACCEPT")
	f.add("netgrip_remote_ssh", "rule", "name", "netgrip-remote-ssh", "src", "wan", "proto", "tcp",
		"dest_port", "22", "target", "ACCEPT")
	return f
}

// fakeLookup answers from m: "TIMEOUT" fails both families, "TIMEOUT6"
// only IPv6. A family with no address answers "no such host", as the
// resolver does.
func fakeLookup(m map[string][]string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if !strings.HasSuffix(host, ".") {
			return nil, errors.New("not queried as an absolute name")
		}
		host = strings.TrimSuffix(host, ".")
		v, ok := m[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var out []netip.Addr
		for _, s := range v {
			if s == "TIMEOUT" || (s == "TIMEOUT6" && network == "ip6") {
				return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true, IsTemporary: true}
			}
			if s == "TIMEOUT6" {
				continue
			}
			a := netip.MustParseAddr(s)
			if a.Is4() == (network == "ip4") {
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return out, nil
	}
}

func ruleBy(t *testing.T, name string) FwdRule {
	t.Helper()
	InvalidatePrefix("")
	for _, r := range ProbeFwd().Rules {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("rule %q not listed", name)
	return FwdRule{}
}

// ---- entries ----

func TestAllowEntryKind(t *testing.T) {
	for _, c := range []struct {
		in, kind, val, err string
	}{
		{"198.51.100.7", "ip", "198.51.100.7/32", ""},
		{" 198.51.100.7 ", "ip", "198.51.100.7/32", ""},
		{"::ffff:198.51.100.7", "ip", "198.51.100.7/32", ""},
		{"2001:db8::5", "ip", "2001:db8::5/128", ""},
		{"198.51.100.9/24", "net", "198.51.100.0/24", ""},
		{"198.51.100.7/32", "ip", "198.51.100.7/32", ""},
		{"2001:db8::/48", "net", "2001:db8::/48", ""},
		{"Home.Example.NET.", "host", "home.example.net", ""},
		{"0.0.0.0/0", "", "", "too wide"},
		{"10.0.0.0/7", "", "", "too wide"},
		{"::/0", "", "", "too wide"},
		{"2001::/15", "", "", "too wide"},
		{"0.0.0.0", "", "", "unspecified"},
		{"127.0.0.1", "", "", "loopback"},
		{"224.0.0.1", "", "", "multicast"},
		{"fe80::1", "", "", "link-local"},
		{"fe80::1%eth0", "", "", "zone"},
		{"localhost", "", "", "not an address"},
		{"bad_name.example.net", "", "", "not an address"},
		{"-x.example.net", "", "", "not an address"},
		{"host.123", "", "", "not an address"},
		{"198.51.100.300", "", "", "not an address"},
		{"", "", "", "empty"},
	} {
		kind, p, host, err := allowEntryKind(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: err %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || kind != c.kind {
			t.Errorf("%q: kind %q err %v", c.in, kind, err)
			continue
		}
		got := host
		if kind != "host" {
			got = p.String()
		}
		if got != c.val {
			t.Errorf("%q: %q, want %q", c.in, got, c.val)
		}
	}
}

func TestAllowValidate(t *testing.T) {
	l, err := allowValidate(AllowList{Name: "  Home\x00 ‮ office  ", KeepHours: 6, Entries: []AllowEntry{
		{Value: "198.51.100.7", Note: "a\nb"}, {Value: "198.51.100.7"}, {Value: "HOME.example.net"}, {Value: "home.example.net."},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "Home office" {
		t.Errorf("name %q", l.Name)
	}
	if len(l.Entries) != 2 || l.Entries[0].Value != "198.51.100.7" || l.Entries[0].Note != "ab" || l.Entries[1].Value != "home.example.net" {
		t.Errorf("entries %+v", l.Entries)
	}
	if _, err := allowValidate(AllowList{Name: "x", KeepHours: 2}); err == nil {
		t.Error("keep 2 accepted")
	}
	if _, err := allowValidate(AllowList{Name: " ", KeepHours: 0}); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := allowValidate(AllowList{Name: "x", Entries: []AllowEntry{{Value: "0.0.0.0/0"}}}); err == nil {
		t.Error("0/0 accepted")
	}
	many := make([]AllowEntry, allowMaxEntries+1)
	for i := range many {
		many[i] = AllowEntry{Value: fmt.Sprintf("198.51.100.%d", i+1)}
	}
	if _, err := allowValidate(AllowList{Name: "x", Entries: many}); err == nil {
		t.Error("too many entries accepted")
	}
}

func TestAllowNewID(t *testing.T) {
	if id := allowNewID("NPM access!", nil); id != "npmaccess" {
		t.Errorf("%q", id)
	}
	if id := allowNewID("Ωμέγα", nil); id != "list" {
		t.Errorf("%q", id)
	}
	if id := allowNewID("Home", map[string]bool{"home": true}); id != "home2" {
		t.Errorf("%q", id)
	}
	if id := allowNewID("averyveryverylongname", nil); !reAllowID.MatchString(id) {
		t.Errorf("%q", id)
	}
}

func TestAllowElementsAndKeep(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	l := AllowList{ID: "t", Name: "t", KeepHours: 6, Entries: []AllowEntry{
		{Value: "198.51.100.0/24"}, {Value: "198.51.100.7"}, {Value: "203.0.113.5"},
		{Value: "a.example.net"}, {Value: "b.example.net"}, {Value: "c.example.net"}, {Value: "2001:db8::/48"},
	}}
	a := netip.MustParseAddr
	hosts := map[string]*allowHost{
		"a.example.net": {V4: allowFam{Addrs: []netip.Addr{a("192.0.2.44")}, OKAt: now}, V6: allowFam{Addrs: []netip.Addr{a("2001:db8::9")}, OKAt: now}},
		// lookups failing for 2 h: kept (6 h allowed)
		"b.example.net": {V4: allowFam{Addrs: []netip.Addr{a("192.0.2.55")}, OKAt: now.Add(-2 * time.Hour), Err: "timeout"}, V6: allowFam{NotFound: true}},
		// the name is gone: dropped at once
		"c.example.net": {V4: allowFam{NotFound: true}, V6: allowFam{NotFound: true}},
	}
	v4, v6 := allowElements(l, hosts, now)
	if strings.Join(v4, ",") != "192.0.2.44,192.0.2.55,198.51.100.0/24,203.0.113.5" {
		t.Errorf("v4 %v", v4)
	}
	if strings.Join(v6, ",") != "2001:db8::/48" { // 2001:db8::9 lies inside
		t.Errorf("v6 %v", v6)
	}
	hosts["b.example.net"].V4.OKAt = now.Add(-7 * time.Hour)
	if v4, _ = allowElements(l, hosts, now); strings.Contains(strings.Join(v4, ","), "192.0.2.55") {
		t.Errorf("kept past the window: %v", v4)
	}
	l.KeepHours = 0
	hosts["b.example.net"].V4.OKAt = now.Add(-time.Second)
	if v4, _ = allowElements(l, hosts, now); strings.Contains(strings.Join(v4, ","), "192.0.2.55") {
		t.Errorf("kept with keep 0: %v", v4)
	}
	// An empty list matches nobody: empty sets, not "everyone".
	if v4, v6 = allowElements(AllowList{ID: "e"}, nil, now); len(v4) != 0 || len(v6) != 0 {
		t.Errorf("empty list: %v %v", v4, v6)
	}
}

func TestAllowCovers(t *testing.T) {
	el := []string{"198.51.100.0/24", "203.0.113.5", "2001:db8::/48"}
	for in, want := range map[string]bool{
		"198.51.100.200": true, "198.51.100.0/25": true, "198.51.0.0/16": false, "203.0.113.5": true,
		"203.0.113.6": false, "2001:db8::1": true, "::ffff:203.0.113.5": true, "junk": false,
	} {
		if got := allowCovers(el, in); got != want {
			t.Errorf("%s: %v", in, got)
		}
	}
}

func TestAllowSetScript(t *testing.T) {
	got := allowSetScript("netgrip_allow_t_v4", []string{"198.51.100.7", "203.0.113.0/24"})
	want := "flush set inet fw4 netgrip_allow_t_v4\nadd element inet fw4 netgrip_allow_t_v4 { 198.51.100.7, 203.0.113.0/24 }\n"
	if got != want {
		t.Errorf("%q", got)
	}
	if got := allowSetScript("s", nil); got != "flush set inet fw4 s\n" {
		t.Errorf("empty: %q", got)
	}
}

// ---- rules ----

func TestAllowSectionFamily(t *testing.T) {
	sec := func(typ string, kv ...string) uciSection {
		s := uciSection{Type: typ, Options: map[string][]string{}}
		for i := 0; i+1 < len(kv); i += 2 {
			s.Options[kv[i]] = append(s.Options[kv[i]], kv[i+1])
		}
		return s
	}
	for i, c := range []struct {
		s    uciSection
		want int
		err  bool
	}{
		{sec("rule"), 0, false},
		{sec("rule", "family", "ipv6"), 6, false},
		{sec("rule", "family", "any"), 0, false},
		{sec("rule", "src_ip", "198.51.100.0/24"), 4, false},
		{sec("rule", "src_ip", "!2001:db8::1"), 6, false},
		{sec("rule", "src_ip", "198.51.100.1 2001:db8::1"), 0, true},
		{sec("rule", "family", "ipv4", "dest_ip", "2001:db8::1"), 0, true},
		{sec("rule", "src_ip", "lan_hosts"), 0, true},
		{sec("rule", "family", "bogus"), 0, true},
		{sec("redirect"), 4, false},
		{sec("redirect", "dest_ip", "192.0.2.10"), 4, false},
		{sec("redirect", "family", "ipv6", "dest_ip", "2001:db8::10"), 6, false},
	} {
		got, err := allowSectionFamily(c.s)
		if (err != nil) != c.err || (!c.err && got != c.want) {
			t.Errorf("case %d: %d %v", i, got, err)
		}
	}
}

func TestAllowAttachOpsForward(t *testing.T) {
	f := baseFW()
	secs := parseUCIShow(f.show(), "firewall")
	ops, sets, err := allowAttachOps(secs, "@redirect[0]", "home", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Args[0] != "firewall.@redirect[0].ipset" || ops[0].Args[1] != "netgrip_allow_home_v4" {
		t.Errorf("ops %+v", ops)
	}
	if len(sets) != 1 || sets[0].Set != "netgrip_allow_home_v4" || sets[0].Name != "Web" {
		t.Errorf("checks %v", sets)
	}
}

func TestAllowAttachOpsDualFamilyAnonymous(t *testing.T) {
	f := baseFW()
	secs := parseUCIShow(f.show(), "firewall")
	old := allowRandName
	allowRandName = func() string { return "abc123" }
	defer func() { allowRandName = old }()
	ops, sets, err := allowAttachOps(secs, "@rule[0]", "home", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ops[0].Kind != "uci_rename" || ops[0].Args[0] != "firewall.@rule[0]" || ops[0].Args[1] != "ngal_abc123" {
		t.Fatalf("first op %+v", ops[0])
	}
	for _, op := range ops {
		if err := executor.Validate(op); err != nil {
			t.Errorf("invalid op %+v: %v", op, err)
		}
	}
	for _, op := range ops {
		if err := f.run(op); err != nil {
			t.Fatal(err)
		}
	}
	o, c := f.find("ngal_abc123"), f.find("ngal_abc123_ngal6")
	if o == nil || c == nil {
		t.Fatalf("rule or twin missing:\n%s", f.show())
	}
	if o.opts["ipset"][0] != "netgrip_allow_home_v4" || o.opts["name"][0] != "VPN-in" {
		t.Errorf("rule %+v", o.opts)
	}
	want := map[string]string{"name": "VPN-in (IPv6, netgrip allowlists)", "family": "ipv6",
		"ipset": "netgrip_allow_home_v6", "src": "wan", "proto": "udp", "dest_port": "51820", "target": "ACCEPT"}
	for k, v := range want {
		if got := c.opts[k]; len(got) != 1 || got[0] != v {
			t.Errorf("twin %s = %v, want %s", k, got, v)
		}
	}
	if len(sets) != 2 || sets[1].Name != "VPN-in (IPv6, netgrip allowlists)" {
		t.Errorf("checks %v", sets)
	}
	// In step now: nothing more to do.
	if ops := allowCompanionSyncOps(parseUCIShow(f.show(), "firewall")); len(ops) != 0 {
		t.Errorf("sync after attach: %+v", ops)
	}
}

func TestAllowCompanionSync(t *testing.T) {
	f := baseFW()
	ssh := f.find("netgrip_remote_ssh")
	ssh.opts["ipset"] = []string{"netgrip_allow_home_v4"}
	ssh.keys = append(ssh.keys, "ipset")
	apply := func() []executor.Op {
		ops := allowCompanionSyncOps(parseUCIShow(f.show(), "firewall"))
		for _, op := range ops {
			if err := f.run(op); err != nil {
				t.Fatal(err)
			}
		}
		return ops
	}
	// Missing: made.
	if ops := apply(); len(ops) == 0 || f.find("netgrip_remote_ssh_ngal6") == nil {
		t.Fatalf("twin not made: %+v", ops)
	}
	if ops := apply(); len(ops) != 0 {
		t.Errorf("not stable: %+v", ops)
	}
	// The rule switched off (remote SSH off: target DROP): the twin follows.
	ssh.opts["target"] = []string{"DROP"}
	apply()
	if got := f.find("netgrip_remote_ssh_ngal6").opts["target"]; got[0] != "DROP" {
		t.Errorf("twin target %v", got)
	}
	// Disabled in LuCI: the twin too.
	ssh.opts["enabled"] = []string{"0"}
	ssh.keys = append(ssh.keys, "enabled")
	apply()
	if got := f.find("netgrip_remote_ssh_ngal6").opts["enabled"]; len(got) != 1 || got[0] != "0" {
		t.Errorf("twin enabled %v", got)
	}
	// The rule went IPv4 only: the twin goes.
	ssh.opts["family"] = []string{"ipv4"}
	ssh.keys = append(ssh.keys, "family")
	apply()
	if f.find("netgrip_remote_ssh_ngal6") != nil {
		t.Error("twin of an IPv4 rule kept")
	}
	// Back to both, then the limit is removed by hand: the twin goes.
	delete(ssh.opts, "family")
	apply()
	if f.find("netgrip_remote_ssh_ngal6") == nil {
		t.Fatal("twin not remade")
	}
	delete(ssh.opts, "ipset")
	apply()
	if f.find("netgrip_remote_ssh_ngal6") != nil {
		t.Error("twin of an unlimited rule kept")
	}
	// The rule deleted: the twin goes.
	ssh.opts["ipset"] = []string{"netgrip_allow_home_v4"}
	apply()
	for i, s := range f.secs {
		if s == ssh {
			f.secs = append(f.secs[:i], f.secs[i+1:]...)
			break
		}
	}
	apply()
	if f.find("netgrip_remote_ssh_ngal6") != nil {
		t.Error("orphan twin kept")
	}
	// A section of someone else's that happens to end in _ngal6 but is not
	// a twin (no list set) is left alone.
	f.add("mine_ngal6", "rule", "name", "mine", "src", "wan", "dest_port", "1", "target", "ACCEPT")
	apply()
	if f.find("mine_ngal6") == nil {
		t.Error("foreign section removed")
	}
}

func TestProbeFwdAllowedFromAndTwinHidden(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	ssh := f.find("netgrip_remote_ssh")
	ssh.opts["ipset"] = []string{"netgrip_allow_home_v4"}
	ssh.keys = append(ssh.keys, "ipset")
	for _, op := range allowCompanionSyncOps(parseUCIShow(f.show(), "firewall")) {
		_ = f.run(op)
	}
	InvalidatePrefix("")
	rules := ProbeFwd().Rules
	var names []string
	for _, r := range rules {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "VPN-in,Web,netgrip-remote-ssh" {
		t.Fatalf("listed %v", names)
	}
	for _, r := range rules {
		switch r.Name {
		case "Web":
			if r.AllowedFrom.Kind != "other" || r.AllowedFrom.Set != "web_allowed" || r.Kind != "forward" ||
				r.DestIP != "192.0.2.10" || r.SrcDport != "443" || r.Proto != "tcp" {
				t.Errorf("Web %+v %+v", r, r.AllowedFrom)
			}
		case "VPN-in":
			if r.AllowedFrom.Kind != "anyone" || r.Section != "@rule[0]" {
				t.Errorf("VPN %+v %+v", r, r.AllowedFrom)
			}
		case "netgrip-remote-ssh":
			if r.AllowedFrom.Kind != "list" || r.AllowedFrom.List != "home" || r.AllowedFrom.Families != "both" {
				t.Errorf("ssh %+v", r.AllowedFrom)
			}
		}
	}
}

// ---- whole changes ----

func TestAllowUseFlow(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	allowLookupFn = fakeLookup(map[string][]string{"home.example.net": {"198.51.100.7", "2001:db8::7"}})
	local := "192.0.2.50"

	if _, err := AllowSave(AllowSaveRequest{Name: "Home", KeepHours: 24, Entries: []AllowEntry{
		{Value: "home.example.net"}, {Value: "203.0.113.0/24", Note: "office"}}}, local); err != nil {
		t.Fatal(err)
	}
	// Saving a list changes nothing in the firewall.
	if len(f.applied) != 0 || f.reloads != 0 {
		t.Fatalf("a list save touched the firewall: %+v", f.applied)
	}
	b, _ := os.ReadFile(allowLoadfile("netgrip_allow_home_v4"))
	if !strings.Contains(string(b), "198.51.100.7\n203.0.113.0/24\n") {
		t.Errorf("v4 file %q", b)
	}

	vpn := ruleBy(t, "VPN-in")
	ref := &AllowRuleRef{Name: vpn.Name, Port: vpn.SrcDport, Proto: vpn.Proto, Kind: vpn.Kind}
	// The page's view went stale: refused.
	if _, _, _, err := AllowUse(AllowUseRequest{Section: vpn.Section, List: "home",
		Expect: &AllowRuleRef{Name: "other", Port: "1", Proto: "udp", Kind: "input"}}, local); err == nil {
		t.Fatal("stale reference accepted")
	}
	if _, _, _, err := AllowUse(AllowUseRequest{Section: vpn.Section, List: "home"}, local); err == nil {
		t.Fatal("anonymous section without details accepted")
	}
	if _, rb, _, err := AllowUse(AllowUseRequest{Section: vpn.Section, List: "home", Expect: ref}, local); err != nil || rb {
		t.Fatalf("attach: rb=%v %v", rb, err)
	}
	vpn = ruleBy(t, "VPN-in")
	if vpn.AllowedFrom.Kind != "list" || vpn.AllowedFrom.Families != "both" || allowAnonymous(vpn.Section) {
		t.Fatalf("after attach %+v %+v", vpn, vpn.AllowedFrom)
	}
	if f.reloads != 1 {
		t.Errorf("reloads %d", f.reloads)
	}
	for _, s := range []string{"netgrip_allow_home_v4", "netgrip_allow_home_v6"} {
		sec := f.find(s)
		if sec == nil || sec.opts["loadfile"][0] != allowLoadfile(s) || sec.opts["match"][0] != "src_net" ||
			!strings.HasPrefix(sec.opts["comment"][0], "netgrip allowlists: ") {
			t.Errorf("set %s: %+v", s, sec)
		}
	}

	// A list in use cannot be deleted.
	if _, _, err := AllowDelete("home", local); err == nil || !strings.Contains(err.Error(), "VPN-in") {
		t.Errorf("delete in use: %v", err)
	}
	// Opening to anyone needs the explicit flag.
	_, _, _, err := AllowUse(AllowUseRequest{Section: vpn.Section, List: ""}, local)
	var nf *AllowNeedsForce
	if !errors.As(err, &nf) {
		t.Fatalf("open without flag: %v", err)
	}
	if _, _, _, err := AllowUse(AllowUseRequest{Section: vpn.Section, List: "", OpenToAnyone: true}, local); err != nil {
		t.Fatal(err)
	}
	vpn = ruleBy(t, "VPN-in")
	if vpn.AllowedFrom.Kind != "anyone" || f.find(vpn.Section+allowCompanionSuffix) != nil {
		t.Errorf("after detach %+v twin=%v", vpn.AllowedFrom, f.find(vpn.Section+allowCompanionSuffix) != nil)
	}
	// Unused now: deleted, sets removed.
	if _, _, err := AllowDelete("home", local); err != nil {
		t.Fatal(err)
	}
	if f.find("netgrip_allow_home_v4") != nil || f.find("netgrip_allow_home_v6") != nil {
		t.Error("sets left behind")
	}
	if _, err := os.Stat(allowLoadfile("netgrip_allow_home_v4")); !os.IsNotExist(err) {
		t.Error("set file left behind")
	}
}

func TestAllowUseLockoutFromOutside(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	if _, err := AllowSave(AllowSaveRequest{Name: "Office", Entries: []AllowEntry{{Value: "203.0.113.0/24"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	ssh := ruleBy(t, "netgrip-remote-ssh")
	outside := "198.51.100.99"
	_, _, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "office"}, outside)
	var nf *AllowNeedsForce
	if !errors.As(err, &nf) || !strings.Contains(nf.Reason, outside) {
		t.Fatalf("lockout not caught: %v", err)
	}
	if len(f.applied) != 0 {
		t.Error("firewall touched before the user confirmed")
	}
	// From inside the office range: fine.
	if _, _, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "office"}, "203.0.113.20"); err != nil {
		t.Fatal(err)
	}
	// Editing the list in use to drop the requester, from outside: refused.
	_, err = AllowSave(AllowSaveRequest{ID: "office", Name: "Office", Entries: []AllowEntry{{Value: "192.0.2.0/24"}}}, "203.0.113.20")
	if !errors.As(err, &nf) {
		t.Fatalf("edit lockout not caught: %v", err)
	}
	if _, err := AllowSave(AllowSaveRequest{ID: "office", Name: "Office", Entries: []AllowEntry{{Value: "192.0.2.0/24"}}, Force: true}, "203.0.113.20"); err != nil {
		t.Fatal(err)
	}
}

func TestAllowUseRollsBackWhenTheFirewallDropsTheRule(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	before := f.show()
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", Entries: []AllowEntry{{Value: "198.51.100.7"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	allowRulesetFn = func() (string, error) { return "", nil } // fw4 skipped the rule
	ssh := ruleBy(t, "netgrip-remote-ssh")
	_, rb, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50")
	if err == nil || !rb {
		t.Fatalf("rb=%v err=%v", rb, err)
	}
	if f.show() != before {
		t.Errorf("config not restored:\n%s", f.show())
	}
	// A failing op: rolled back too.
	allowRulesetFn = func() (string, error) { return "@netgrip_allow_home_v4 x", nil }
	f.failOn = "uci_set firewall.netgrip_remote_ssh.ipset"
	_, rb, _, err = AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50")
	if err == nil || !rb || f.show() != before {
		t.Errorf("failed op: rb=%v err=%v", rb, err)
	}
}

func TestAddFwdRuleWithList(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	old := applyForFwdTest(t, f)
	defer old()
	if _, err := AllowSave(AllowSaveRequest{Name: "Friends", Entries: []AllowEntry{{Value: "198.51.100.7"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddFwdRule("25565", "192.0.2.20", "25565", "tcp", "nope"); err == nil {
		t.Fatal("unknown list accepted")
	}
	if f.find("netgrip_fwd_25565_192_0_2_20") != nil {
		t.Fatal("forward created with an unknown list")
	}
	if _, rb, err := AddFwdRule("25565", "192.0.2.20", "25565", "tcp", "friends"); err != nil || rb {
		t.Fatalf("rb=%v %v", rb, err)
	}
	r := f.find("netgrip_fwd_25565_192_0_2_20")
	if r == nil || r.opts["ipset"][0] != "netgrip_allow_friends_v4" {
		t.Fatalf("forward %+v", r)
	}
	// Its options were set in the same apply as the limit: never open.
	if len(f.applied) != 1 {
		t.Errorf("applies %d", len(f.applied))
	}
}

// applyForFwdTest sends the port forward code's executor calls to f.
func applyForFwdTest(t *testing.T, f *fakeFW) func() {
	t.Helper()
	oldA, oldS, oldR, oldRun, oldEn := fwdApplyFn, fwdSnapshotFn, fwdRestoreFn, fwdRunFn, fwdFirewallEnabledFn
	fwdApplyFn = allowApplyFn
	fwdSnapshotFn = allowSnapshotFn
	fwdRestoreFn = allowRestoreFn
	fwdRunFn = f.run
	fwdFirewallEnabledFn = func() bool { return true }
	return func() {
		fwdApplyFn, fwdSnapshotFn, fwdRestoreFn, fwdRunFn, fwdFirewallEnabledFn = oldA, oldS, oldR, oldRun, oldEn
	}
}

func TestAllowRefreshPushesOnlyChanges(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	answers := map[string][]string{"home.example.net": {"198.51.100.7"}}
	allowLookupFn = fakeLookup(answers)
	var scripts []string
	allowNftFn = func(s string) error { scripts = append(scripts, s); return nil }
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", KeepHours: 1, Entries: []AllowEntry{{Value: "home.example.net"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	// Not in the firewall yet: files only, no nft.
	if len(scripts) != 0 {
		t.Fatalf("nft for a set not in use: %v", scripts)
	}
	ssh := ruleBy(t, "netgrip-remote-ssh")
	if _, _, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	scripts = nil
	allowRefresh(false)
	if len(scripts) != 0 {
		t.Errorf("unchanged sets refilled: %v", scripts)
	}
	answers["home.example.net"] = []string{"198.51.100.8"}
	allowRefresh(false)
	if len(scripts) != 1 || !strings.Contains(scripts[0], "{ 198.51.100.8 }") || !strings.HasPrefix(scripts[0], "flush set inet fw4 netgrip_allow_home_v4\n") {
		t.Fatalf("change not pushed: %q", scripts)
	}
	b, _ := os.ReadFile(allowLoadfile("netgrip_allow_home_v4"))
	if !strings.Contains(string(b), "198.51.100.8") || strings.Contains(string(b), "198.51.100.7") {
		t.Errorf("file %q", b)
	}
	scripts = nil
	allowRefresh(true)
	if len(scripts) != 2 {
		t.Errorf("forced refill: %d scripts", len(scripts))
	}
	// DNS down: the address is kept (within the hour)...
	answers["home.example.net"] = []string{"TIMEOUT"}
	scripts = nil
	allowRefresh(false)
	if len(scripts) != 0 {
		t.Errorf("a failed lookup changed the set: %q", scripts)
	}
	// ...and dropped once the hour is over.
	allowMu.Lock()
	allowHosts["home.example.net"].V4.OKAt = allowNow().Add(-2 * time.Hour)
	allowMu.Unlock()
	allowRefresh(false)
	if len(scripts) != 1 || strings.Contains(scripts[0], "198.51.100.8") {
		t.Errorf("stale address kept: %q", scripts)
	}
	// The name removed from DNS: dropped at once.
	answers["home.example.net"] = []string{"198.51.100.8"}
	allowRefresh(false)
	delete(answers, "home.example.net")
	scripts = nil
	allowRefresh(false)
	if len(scripts) != 1 || strings.Contains(scripts[0], "198.51.100.8") {
		t.Errorf("gone name kept: %q", scripts)
	}
	// nft failing: retried next time.
	allowNftFn = func(string) error { return errors.New("No such file or directory") }
	answers["home.example.net"] = []string{"198.51.100.9"}
	allowRefresh(false)
	scripts = nil
	allowNftFn = func(s string) error { scripts = append(scripts, s); return nil }
	allowRefresh(false)
	if len(scripts) != 1 || !strings.Contains(scripts[0], "198.51.100.9") {
		t.Errorf("failed refill not retried: %q", scripts)
	}
}

func TestAllowRefreshNothingWithoutLists(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	lookups := 0
	allowLookupFn = func(context.Context, string, string) ([]netip.Addr, error) { lookups++; return nil, nil }
	allowNftFn = func(string) error { t.Error("nft ran"); return nil }
	calls := 0
	SetUciExecForTest(t, func(args ...string) ([]byte, error) { calls++; return nil, errors.New("x") })
	allowRefresh(true)
	allowSyncCompanionsTick()
	if lookups != 0 || calls != 0 {
		t.Errorf("idle work: %d lookups, %d uci calls", lookups, calls)
	}
}

func TestAllowUsableAddrs(t *testing.T) {
	a := netip.MustParseAddr
	got := allowUsableAddrs([]netip.Addr{a("203.0.113.9"), a("::ffff:198.51.100.1"), a("127.0.0.1"), a("0.0.0.0"),
		a("fe80::1"), a("203.0.113.9"), a("2001:db8::1")})
	var s []string
	for _, x := range got {
		s = append(s, x.String())
	}
	if strings.Join(s, ",") != "198.51.100.1,203.0.113.9,2001:db8::1" {
		t.Errorf("%v", s)
	}
}

// ---- requester ----

func TestAllowRequesterLocal(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	clientSubnetsFn = func() []ubus.Subnet {
		return []ubus.Subnet{
			{Interface: "lan", Address: "192.0.2.1", Mask: 24},
			{Interface: "wan", Address: "198.51.100.2", Mask: 24}, // the uplink's own subnet
			{Interface: "vpn", Address: "203.0.113.1", Mask: 32},
		}
	}
	for ip, want := range map[string]bool{
		// Loopback is how an SSH tunnel arrives, from anywhere: not local.
		"192.0.2.77": true, "::ffff:192.0.2.77": true, "127.0.0.1": false, "fd00::5": true, "fe80::1": true,
		// The host a port open to the Internet forwards to (a reverse proxy
		// passes on the Internet's requests): not local.
		"192.0.2.10":   false,
		"198.51.100.9": false, "203.0.113.1": false, "2001:db8::1": false, "": false, "junk": false,
	} {
		if got := AllowRequesterLocal(ip); got != want {
			t.Errorf("%q: %v", ip, got)
		}
	}
}

// ---- sets NetGrip does not manage ----

func TestParseNftElements(t *testing.T) {
	text := `table inet fw4 {
	set web_allowed {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.7, 203.0.113.0/24,
			     192.0.2.9 timeout 1h expires 59m }
	}
}`
	if got := strings.Join(parseNftElements(text), ","); got != "198.51.100.7,203.0.113.0/24,192.0.2.9" {
		t.Errorf("%q", got)
	}
	if got := parseNftElements("set x {\n type ipv4_addr\n}"); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestAllowMentions(t *testing.T) {
	for s, want := range map[string]bool{
		`SET_NAME="web_allowed"`: true, "nft flush set inet fw4 web_allowed": true,
		"web_allowed2": false, "my_web_allowed": false, "web-allowed": false,
	} {
		if got := allowMentions(s, "web_allowed"); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestAllowCronWritersAndTakeoverInfo(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	dir := t.TempDir()
	old := allowCrontabDir
	allowCrontabDir = filepath.Join(dir, "crontabs")
	defer func() { allowCrontabDir = old }()
	_ = os.MkdirAll(allowCrontabDir, 0o755)
	script := filepath.Join(dir, "update.sh")
	_ = os.WriteFile(script, []byte(`#!/bin/sh
SET_NAME="web_allowed"
HOSTS="
alpha.example.net
beta.example.org
"
nft flush set inet fw4 "$SET_NAME"
logger "see docs.example.com"
`), 0o755)
	tab := filepath.Join(allowCrontabDir, "root")
	_ = os.WriteFile(tab, []byte("*/4 * * * * /bin/true\n*/5 * * * * "+script+"\n# */5 * * * * "+script+"\n"), 0o600)
	fwList := allowNftListFn
	allowNftListFn = func(set string) (string, error) {
		if set == "web_allowed" {
			return "set web_allowed {\n elements = { 198.51.100.7, 203.0.113.44 }\n}", nil
		}
		return fwList(set)
	}
	allowLookupFn = fakeLookup(map[string][]string{
		"alpha.example.net": {"198.51.100.7"},
		"docs.example.com":  {"192.0.2.200"}, // a name in the script, not in the set
	})
	info, err := AllowTakeoverInfo("web_allowed")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Manage || len(info.Writers) != 1 || !strings.Contains(info.Writers[0], script) {
		t.Fatalf("info %+v", info)
	}
	var sug []string
	for _, e := range info.Suggest {
		sug = append(sug, e.Value)
	}
	if strings.Join(sug, ",") != "alpha.example.net,203.0.113.44" {
		t.Errorf("suggestions %v", sug)
	}

	// Take it over, from inside.
	if _, _, err := AllowTakeover(AllowTakeoverRequest{Set: "web_allowed", Name: "Web access",
		Entries: info.Suggest}, "198.51.100.50"); err == nil {
		t.Fatal("take over from outside accepted")
	}
	_, _, err = AllowTakeover(AllowTakeoverRequest{Set: "web_allowed", Name: "Web access",
		Entries: []AllowEntry{{Value: "alpha.example.net"}}}, "192.0.2.50")
	var nf *AllowNeedsForce
	if !errors.As(err, &nf) || !strings.Contains(nf.Reason, "203.0.113.44") {
		t.Fatalf("missing address not caught: %v", err)
	}
	if _, rb, err := AllowTakeover(AllowTakeoverRequest{Set: "web_allowed", Name: "Web access",
		Entries: info.Suggest}, "192.0.2.50"); err != nil || rb {
		t.Fatalf("take over: rb=%v %v", rb, err)
	}
	web := ruleBy(t, "Web")
	if web.AllowedFrom.Kind != "list" || web.AllowedFrom.Set != "netgrip_allow_webaccess_v4" {
		t.Errorf("Web after take over %+v", web.AllowedFrom)
	}
	for _, s := range f.secs {
		if s.typ == "ipset" && s.opts["name"][0] == "web_allowed" {
			t.Error("old set left in the config")
		}
	}
	tabNow, _ := os.ReadFile(tab)
	lines := strings.Split(string(tabNow), "\n")
	if lines[0] != "*/4 * * * * /bin/true" || !strings.HasPrefix(lines[1], `# netgrip allowlists: replaced by the list "Web access": */5`) ||
		lines[2] != "# */5 * * * * "+script {
		t.Errorf("crontab:\n%s", tabNow)
	}
}

func TestAllowExternalNotManageable(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	f.add("", "ipset", "name", "blocked", "match", "src_ip")
	f.add("", "redirect", "name", "Cam", "src", "wan", "src_dport", "8554", "dest", "lan",
		"dest_ip", "192.0.2.11", "dest_port", "554", "proto", "tcp", "ipset", "!blocked")
	f.add("", "ipset", "name", "macs", "match", "src_mac")
	f.add("", "ipset", "name", "unused", "match", "src_ip")
	InvalidatePrefix("")
	ext := allowExternalSets(allowSections(), ProbeFwd().Rules)
	why := map[string]string{}
	for _, e := range ext {
		why[e.Set] = e.Why
		if e.Manage != (e.Why == "") {
			t.Errorf("%s: manage %v why %q", e.Set, e.Manage, e.Why)
		}
	}
	if !strings.Contains(why["blocked"], "block") || !strings.Contains(why["macs"], "other than addresses") ||
		!strings.Contains(why["unused"], "no port") || why["web_allowed"] != "" {
		t.Errorf("why %v", why)
	}
}

func TestExecutorRenameValidation(t *testing.T) {
	ok := executor.Op{Kind: "uci_rename", Args: []string{"firewall.@rule[3]", "ngal_abc123"}}
	if err := executor.Validate(ok); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]string{
		{"firewall.@rule[3].name", "x"}, {"firewall", "x"}, {"firewall.x", "a-b"}, {"firewall.x", ""}, {"firewall.x", "a;b"},
	} {
		if err := executor.Validate(executor.Op{Kind: "uci_rename", Args: bad}); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestAllowDeleteOrder(t *testing.T) {
	got := strings.Join(allowDeleteOrder([]string{"@ipset[0]", "named", "@ipset[10]", "@ipset[2]"}), ",")
	if got != "@ipset[10],@ipset[2],@ipset[0],named" {
		t.Errorf("%s", got)
	}
	// Two sets with the same name deleted in one batch: both go, and the
	// third set stays.
	f := &fakeFW{}
	f.add("", "ipset", "name", "dup")
	f.add("", "ipset", "name", "keep")
	f.add("", "ipset", "name", "dup")
	for _, n := range allowDeleteOrder([]string{"@ipset[0]", "@ipset[2]"}) {
		if err := f.run(executor.Op{Kind: "uci_delete", Args: []string{"firewall." + n}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.secs) != 1 || f.secs[0].opts["name"][0] != "keep" {
		t.Errorf("left %s", f.show())
	}
}

// ---- review findings ----

func TestIpsetRefNegationWithSpace(t *testing.T) {
	for in, want := range map[string]string{"trusted": "trusted", "!trusted": "!trusted", "! trusted": "!trusted",
		"  !  trusted src": "!trusted", "": "", "!": "!"} {
		n, neg := ipsetRef(in)
		got := n
		if neg {
			got = "!" + n
		}
		if got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	// A DROP rule written "! trusted" is a reference: the set cannot be
	// taken over (deleting it would make fw4 skip the DROP rule).
	f := baseFW()
	installFakeFW(t, f)
	f.add("", "ipset", "name", "trusted", "match", "src_ip")
	f.add("", "rule", "name", "Block-SSH", "src", "wan", "proto", "tcp", "dest_port", "22", "target", "DROP", "ipset", "! trusted")
	f.add("", "rule", "name", "SSH-in", "src", "wan", "proto", "tcp", "dest_port", "22", "target", "ACCEPT", "ipset", "trusted")
	secs := parseUCIShow(f.show(), "firewall")
	if refs := allowReferences(secs, "trusted"); len(refs) != 2 {
		t.Errorf("refs %v", refs)
	}
	InvalidatePrefix("")
	for _, e := range allowExternalSets(allowSections(), ProbeFwd().Rules) {
		if e.Set == "trusted" && e.Manage {
			t.Error("a set a DROP rule uses offered for take over")
		}
	}
}

func TestTakeoverKeepsTheFamily(t *testing.T) {
	// A rule answering both families, limited to an IPv4 set elsewhere,
	// only let IPv4 in: after the take over it must not let IPv6 in.
	f := baseFW()
	vpn := f.find("@rule[0]")
	vpn.opts["ipset"] = []string{"web_allowed"}
	vpn.keys = append(vpn.keys, "ipset")
	secs := parseUCIShow(f.show(), "firewall")
	ops, checks, err := allowAttachOps(secs, "@rule[0]", "home", 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if err := f.run(op); err != nil {
			t.Fatal(err)
		}
	}
	if vpn.opts["family"][0] != "ipv4" || vpn.opts["ipset"][0] != "netgrip_allow_home_v4" || len(checks) != 1 {
		t.Errorf("rule %+v checks %v", vpn.opts, checks)
	}
	for _, s := range f.secs {
		if strings.HasSuffix(f.label(s), allowCompanionSuffix) {
			t.Error("IPv6 twin made")
		}
	}
	// The background check does not add one later either.
	if ops := allowCompanionSyncOps(parseUCIShow(f.show(), "firewall")); len(ops) != 0 {
		t.Errorf("sync %+v", ops)
	}
	// An IPv4 rule with an IPv6 set: refused (fw4 skipped it before).
	if _, _, err := allowAttachOps(parseUCIShow(f.show(), "firewall"), "@redirect[0]", "home", 6); err == nil {
		t.Error("family mismatch accepted")
	}
}

func TestCompanionSettlesWithOddOptions(t *testing.T) {
	f := baseFW()
	ssh := f.find("netgrip_remote_ssh")
	ssh.opts["ipset"] = []string{"netgrip_allow_home_v4"}
	ssh.opts["icmp_type"] = nil // `uci show` prints an empty list as "key="
	ssh.keys = append(ssh.keys, "ipset", "icmp_type")
	ssh.opts["name"] = []string{"ssh; `x`"}
	sync := func() []executor.Op {
		ops := allowCompanionSyncOps(parseUCIShow(f.show(), "firewall"))
		for _, op := range ops {
			if err := f.run(op); err != nil {
				t.Fatalf("%+v: %v", op, err)
			}
		}
		return ops
	}
	sync()
	if ops := sync(); len(ops) != 0 {
		t.Fatalf("does not settle: %+v", ops)
	}
	if n := f.find("netgrip_remote_ssh_ngal6").opts["name"][0]; n != "ssh x (IPv6, netgrip allowlists)" {
		t.Errorf("twin name %q", n)
	}
	// A value NetGrip cannot write: no twin (IPv6 closed), and stable.
	ssh.opts["extra"] = []string{"a;b"}
	ssh.keys = append(ssh.keys, "extra")
	sync()
	if f.find("netgrip_remote_ssh_ngal6") != nil {
		t.Error("twin kept for a rule it cannot copy")
	}
	if ops := sync(); len(ops) != 0 {
		t.Errorf("does not settle: %+v", ops)
	}
	InvalidatePrefix("")
	af := allowedFromOf("netgrip_remote_ssh", parseUCIShow(f.show(), "firewall")["netgrip_remote_ssh"], parseUCIShow(f.show(), "firewall"), nil)
	if !af.IPv6Closed || af.Families != "ipv4" {
		t.Errorf("%+v", af)
	}
}

func TestTwinOutOfStepIsListed(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	ssh := f.find("netgrip_remote_ssh")
	ssh.opts["ipset"] = []string{"netgrip_allow_home_v4"}
	ssh.keys = append(ssh.keys, "ipset")
	for _, op := range allowCompanionSyncOps(parseUCIShow(f.show(), "firewall")) {
		_ = f.run(op)
	}
	ssh.opts["dest_port"] = []string{"2222"} // changed in LuCI, twin not repaired yet
	InvalidatePrefix("")
	found := false
	for _, r := range ProbeFwd().Rules {
		if r.Section == "netgrip_remote_ssh_ngal6" && r.SrcDport == "22" {
			found = true
		}
	}
	if !found {
		t.Error("a twin out of step is hidden")
	}
}

func TestDNSPerFamilyAndParked(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	answers := map[string][]string{"home.example.net": {"198.51.100.7", "2001:db8::7"}}
	allowLookupFn = fakeLookup(answers)
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", KeepHours: 6, Entries: []AllowEntry{{Value: "home.example.net"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	// IPv6 times out, IPv4 moves: the IPv6 address is kept, the new IPv4
	// one used.
	answers["home.example.net"] = []string{"198.51.100.8", "TIMEOUT6"}
	allowRefresh(false)
	allowMu.Lock()
	_, l := allowFindLocked("home")
	v4, v6 := allowElements(*l, allowHosts, allowNow())
	allowMu.Unlock()
	if strings.Join(v4, ",") != "198.51.100.8" || strings.Join(v6, ",") != "2001:db8::7" {
		t.Errorf("v4 %v v6 %v", v4, v6)
	}
	// Parked at 0.0.0.0: gone at once, not "failing".
	answers["home.example.net"] = []string{"0.0.0.0"}
	allowRefresh(false)
	allowMu.Lock()
	v4, v6 = allowElements(*l, allowHosts, allowNow())
	allowMu.Unlock()
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("parked name kept: %v %v", v4, v6)
	}
}

func TestRefillFailureEmptiesTheSet(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	allowLookupFn = fakeLookup(map[string][]string{"home.example.net": {"198.51.100.7"}})
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", Entries: []AllowEntry{{Value: "home.example.net"}, {Value: "203.0.113.5"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	ssh := ruleBy(t, "netgrip-remote-ssh")
	if _, _, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	var scripts []string
	allowNftFn = func(s string) error {
		scripts = append(scripts, s)
		if strings.Contains(s, "add element") {
			return errors.New("Could not process rule")
		}
		return nil
	}
	allowRefresh(true)
	flushOnly := 0
	for _, s := range scripts {
		if s == "flush set inet fw4 netgrip_allow_home_v4\n" {
			flushOnly++
		}
	}
	if flushOnly != 1 {
		t.Errorf("not emptied on failure: %q", scripts)
	}
	p := ProbeAllowlists("192.0.2.50")
	if p.Lists[0].Error == "" {
		t.Error("failure not shown")
	}
}

func TestRangePrefixes(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.0-198.51.100.255": "198.51.100.0/24",
		"198.51.100.5-198.51.100.9":   "198.51.100.5,198.51.100.6/31,198.51.100.8/31",
		"198.51.100.7-198.51.100.7":   "198.51.100.7",
		"2001:db8::-2001:db8::3":      "2001:db8::/126",
		"198.51.100.9-198.51.100.5":   "",
	} {
		a, b, _ := strings.Cut(in, "-")
		if got := strings.Join(rangePrefixes(a, b), ","); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	text := "set s {\n elements = { 198.51.100.0-198.51.100.3, 203.0.113.9 }\n}"
	if got := strings.Join(parseNftElements(text), ","); got != "198.51.100.0/30,203.0.113.9" {
		t.Errorf("%s", got)
	}
}

func TestCronLineChangedMeanwhileIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	tabs := filepath.Join(dir, "crontabs")
	_ = os.MkdirAll(tabs, 0o755)
	tab := filepath.Join(tabs, "root")
	_ = os.WriteFile(tab, []byte("*/5 * * * * /usr/bin/other\n"), 0o600)
	err := allowDisableCronLines([]allowCronLine{{File: tab, Line: 1, Text: "*/5 * * * * /usr/bin/fill-web"}}, "x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(tab)
	if string(b) != "*/5 * * * * /usr/bin/other\n" {
		t.Errorf("%q", b)
	}
	entries, _ := os.ReadDir(tabs)
	if len(entries) != 1 {
		t.Errorf("stray files in the crontab dir: %v", entries)
	}
}

func TestAllowUseNoopAndRemoteOff(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", Entries: []AllowEntry{{Value: "192.0.2.0/24"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	ssh := ruleBy(t, "netgrip-remote-ssh")
	_, _, changed, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50")
	if err != nil || !changed {
		t.Fatalf("changed=%v %v", changed, err)
	}
	reloads := f.reloads
	if _, _, changed, err = AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50"); err != nil || changed || f.reloads != reloads {
		t.Errorf("no-op reloaded: changed=%v reloads %d->%d %v", changed, reloads, f.reloads, err)
	}
	// Remote SSH switched off (DROP): not listed, but its list can be
	// released, so the list can be deleted.
	f.find("netgrip_remote_ssh").opts["target"] = []string{"DROP"}
	InvalidatePrefix("")
	if _, _, _, err := AllowUse(AllowUseRequest{Section: "netgrip_remote_ssh", OpenToAnyone: true}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AllowDelete("home", "192.0.2.50"); err != nil {
		t.Errorf("list stuck: %v", err)
	}
}

func TestAddFwdRuleLimitStagedFirst(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	defer applyForFwdTest(t, f)()
	if _, err := AllowSave(AllowSaveRequest{Name: "Friends", Entries: []AllowEntry{{Value: "198.51.100.7"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddFwdRule("8443", "192.0.2.20", "443", "tcp", "friends"); err != nil {
		t.Fatal(err)
	}
	ops := f.applied[len(f.applied)-1]
	for i, op := range ops {
		if op.Args[0] == "firewall.netgrip_fwd_8443_192_0_2_20" {
			if next := ops[i+1]; next.Args[0] != "firewall.netgrip_fwd_8443_192_0_2_20.ipset" {
				t.Errorf("limit not staged right after the section: %+v", next)
			}
			return
		}
	}
	t.Error("forward section not created")
}

func TestPendingChangesRefused(t *testing.T) {
	f := baseFW()
	installFakeFW(t, f)
	if _, err := AllowSave(AllowSaveRequest{Name: "Home", Entries: []AllowEntry{{Value: "192.0.2.0/24"}}}, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	ssh := ruleBy(t, "netgrip-remote-ssh")
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "changes" {
			return []byte("firewall.x.ipset='-'\n"), nil
		}
		if len(args) == 2 && args[0] == "show" {
			return []byte(f.show()), nil
		}
		return nil, errors.New("not found")
	})
	InvalidatePrefix("")
	if _, _, _, err := AllowUse(AllowUseRequest{Section: ssh.Section, List: "home"}, "192.0.2.50"); !errors.Is(err, errAllowPending) {
		t.Errorf("err %v", err)
	}
	if len(f.applied) != 0 {
		t.Error("applied over someone else's staged changes")
	}
}
