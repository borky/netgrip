package modules

// Allow lists, the firewall side: which rules a list limits, and the
// changes that tie a list to a rule, untie it, keep the IPv6 twin of a rule
// in step, and take over a set something else used to fill.
//
// A list is tied to a rule with the rule's "ipset" option. fw4 limits a rule
// that uses a set to the set's family, so:
//
//   - a port forward is IPv4 (its destination is): it gets the IPv4 set;
//   - a port on the router that answers both families gets the IPv4 set,
//     and a twin rule (the "companion", <section>_ngal6) is added for IPv6
//     with the IPv6 set. Without the twin, IPv6 would simply be closed for
//     that port. The twin copies the rule's options, and is rewritten or
//     removed when the rule changes or goes (checked every two minutes and
//     after each of NetGrip's own changes). An anonymous rule (one LuCI
//     created) is given a name first: its index moves when other rules
//     come and go, its name does not.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

const allowCompanionSuffix = "_ngal6"

// fwWriteMu serialises NetGrip's firewall writes that allow lists take
// part in (lists, port forwards, remote access), so the twin-rule check
// never runs in the middle of one.
var fwWriteMu sync.Mutex

var reAnonSection = regexp.MustCompile(`^(@[a-z_-]+\[\d+\]|cfg[0-9a-f]{6})$`)

// Seams for tests.
var (
	allowSnapshotFn = executor.Snapshot
	allowRestoreFn  = executor.Restore
	allowApplyFn    = executor.Apply
	allowRunFn      = executor.Run
	allowNftListFn  = func(set string) (string, error) {
		out, err := exec.Command("nft", "list", "set", "inet", "fw4", set).CombinedOutput()
		return string(out), err
	}
	allowRulesetFn = func() (string, error) {
		out, err := exec.Command("nft", "list", "table", "inet", "fw4").Output()
		return string(out), err
	}
	allowCrontabDir = "/etc/crontabs"
	allowRandName   = func() string {
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
)

// AllowedFrom says who may reach a port.
type AllowedFrom struct {
	// Kind: "anyone"; "list" (one of NetGrip's lists); "other" (a set
	// NetGrip does not manage).
	Kind     string `json:"kind"`
	List     string `json:"list,omitempty"`
	ListName string `json:"list_name,omitempty"`
	Set      string `json:"set,omitempty"`
	Negated  bool   `json:"negated,omitempty"` // "other": everyone BUT the set
	// Families: which address families the limit lets in: "ipv4", "ipv6"
	// or "both" (for "list"). A port that answered both and lost IPv6
	// reads "ipv4".
	Families string `json:"families,omitempty"`
}

// AllowRuleRef identifies a rule as the page saw it: an anonymous rule's
// index can point at another rule by the time a change arrives.
type AllowRuleRef struct {
	Name  string `json:"name"`
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Kind  string `json:"kind"`
}

// allowSections is the firewall config, fresh.
func allowSections() map[string]uciSection {
	InvalidateKey("ucishow|firewall")
	show, ok := uciShowCached("firewall")
	if !ok {
		return map[string]uciSection{}
	}
	return parseUCIShow(show, "firewall")
}

func allowAnonymous(section string) bool { return reAnonSection.MatchString(section) }

// allowSetOf reads a rule's set: the list id and family when it is one of
// NetGrip's lists and not negated.
func allowSetOf(s uciSection) (id string, family int, ok bool) {
	f := strings.Fields(s.Option("ipset"))
	if len(f) == 0 || strings.HasPrefix(f[0], "!") {
		return "", 0, false
	}
	m := reAllowSet.FindStringSubmatch(f[0])
	if m == nil {
		return "", 0, false
	}
	if m[2] == "4" {
		return m[1], 4, true
	}
	return m[1], 6, true
}

// allowIsCompanion: section is an IPv6 twin NetGrip made.
func allowIsCompanion(name string, s uciSection) bool {
	if !strings.HasSuffix(name, allowCompanionSuffix) || s.Type != "rule" {
		return false
	}
	_, fam, ok := allowSetOf(s)
	return ok && fam == 6
}

func parseAddrOrPrefix(v string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(v)
}

// allowSectionFamily is the family a rule or forward answers: 4, 6 or 0
// (both), as fw4 works it out.
func allowSectionFamily(s uciSection) (int, error) {
	fam := 0
	switch strings.ToLower(s.Option("family")) {
	case "ipv4", "4":
		fam = 4
	case "ipv6", "6":
		fam = 6
	case "", "any", "all":
	default:
		return 0, fmt.Errorf("the rule's family %q is not one NetGrip knows", s.Option("family"))
	}
	has4, has6 := false, false
	for _, k := range []string{"src_ip", "dest_ip", "src_dip"} {
		for _, v := range s.Options[k] {
			for _, f := range strings.Fields(v) {
				a, err := parseAddrOrPrefix(strings.TrimPrefix(f, "!"))
				if err != nil {
					return 0, fmt.Errorf("the rule's %s %q is not an address NetGrip can read", k, f)
				}
				if a.Unmap().Is4() {
					has4 = true
				} else {
					has6 = true
				}
			}
		}
	}
	switch {
	case has4 && has6:
		return 0, errors.New("the rule mixes IPv4 and IPv6 addresses")
	case fam == 4 && has6, fam == 6 && has4:
		return 0, errors.New("the rule's family and its addresses disagree")
	case has4:
		fam = 4
	case has6:
		fam = 6
	}
	// fw4 makes a forward with no family and no address IPv4.
	if fam == 0 && s.Type == "redirect" {
		fam = 4
	}
	return fam, nil
}

// allowedFromOf describes who may reach a rule now.
func allowedFromOf(name string, s uciSection, secs map[string]uciSection, names map[string]string) AllowedFrom {
	f := strings.Fields(s.Option("ipset"))
	if len(f) == 0 {
		return AllowedFrom{Kind: "anyone"}
	}
	set := strings.TrimPrefix(f[0], "!")
	id, fam, ok := allowSetOf(s)
	if !ok {
		return AllowedFrom{Kind: "other", Set: set, Negated: strings.HasPrefix(f[0], "!")}
	}
	a := AllowedFrom{Kind: "list", List: id, ListName: names[id], Set: set, Families: fmt.Sprintf("ipv%d", fam)}
	if fam == 4 && s.Type == "rule" {
		if c, ok := secs[name+allowCompanionSuffix]; ok && allowIsCompanion(name+allowCompanionSuffix, c) {
			a.Families = "both"
		}
	}
	return a
}

// ---- plans (pure: the uci changes, nothing run) ----

func setOp(key, val string) executor.Op {
	return executor.Op{Kind: "uci_set", Args: []string{key, val}}
}

// allowSetWant is how a list's set section must read.
func allowSetWant(id string, fam int) map[string][]string {
	set := allowSetName(id, fam)
	return map[string][]string{
		"name":     {set},
		"family":   {fmt.Sprintf("ipv%d", fam)},
		"match":    {"src_net"},
		"loadfile": {allowLoadfile(set)},
		"comment":  {fmt.Sprintf("netgrip allowlists: list %s (IPv%d)", id, fam)},
	}
}

func optionsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || len(v) != len(w) {
			return false
		}
		for i := range v {
			if v[i] != w[i] {
				return false
			}
		}
	}
	return true
}

// sectionOps writes a whole section from scratch.
func sectionOps(section, typ string, opts map[string][]string) []executor.Op {
	base := "firewall." + section
	ops := []executor.Op{setOp(base, typ)}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := opts[k]
		if len(v) == 1 && k != "match" {
			ops = append(ops, setOp(base+"."+k, v[0]))
			continue
		}
		for _, x := range v {
			ops = append(ops, executor.Op{Kind: "uci_add_list", Args: []string{base + "." + k, x}})
		}
	}
	return ops
}

// allowEnsureSetOps creates or repairs a list's two set sections.
func allowEnsureSetOps(secs map[string]uciSection, id string) ([]executor.Op, error) {
	var ops []executor.Op
	for _, fam := range []int{4, 6} {
		set := allowSetName(id, fam)
		for name, s := range secs {
			if s.Type == "ipset" && s.Option("name") == set && name != set {
				return nil, fmt.Errorf("another firewall set is already called %s", set)
			}
		}
		want := allowSetWant(id, fam)
		if s, ok := secs[set]; ok && s.Type == "ipset" && optionsEqual(s.Options, want) {
			continue
		}
		if _, ok := secs[set]; ok {
			ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + set}})
		}
		ops = append(ops, sectionOps(set, "ipset", want)...)
	}
	return ops, nil
}

// allowCompanionWant is how the IPv6 twin of rule o must read.
func allowCompanionWant(o uciSection, id string) map[string][]string {
	want := map[string][]string{}
	for k, v := range o.Options {
		switch k {
		case "name", "ipset", "family":
			continue
		}
		want[k] = append([]string(nil), v...)
	}
	name := o.Option("name")
	if name == "" {
		name = "rule"
	}
	want["name"] = []string{name + " (IPv6, netgrip allowlists)"}
	want["family"] = []string{"ipv6"}
	want["ipset"] = []string{allowSetName(id, 6)}
	return want
}

// allowCompanionOps makes twin c of rule o read as it must (nothing when
// it already does).
func allowCompanionOps(c string, o uciSection, id string, existing *uciSection) []executor.Op {
	want := allowCompanionWant(o, id)
	if existing != nil && existing.Type == "rule" && optionsEqual(existing.Options, want) {
		return nil
	}
	var ops []executor.Op
	if existing != nil {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + c}})
	}
	return append(ops, sectionOps(c, "rule", want)...)
}

// allowCompanionSyncOps brings every twin in step with its rule: made when
// missing, rewritten when the rule changed, removed when the rule went or
// no longer uses a list for both families.
func allowCompanionSyncOps(secs map[string]uciSection) []executor.Op {
	names := make([]string, 0, len(secs))
	for n := range secs {
		names = append(names, n)
	}
	sort.Strings(names)
	var ops []executor.Op
	for _, name := range names {
		s := secs[name]
		if s.Type != "rule" || allowIsCompanion(name, s) || allowAnonymous(name) {
			continue
		}
		id, fam, ok := allowSetOf(s)
		if !ok || fam != 4 {
			continue
		}
		if f, err := allowSectionFamily(s); err != nil || f != 0 {
			continue
		}
		c := name + allowCompanionSuffix
		var ex *uciSection
		if cs, ok := secs[c]; ok {
			ex = &cs
		}
		ops = append(ops, allowCompanionOps(c, s, id, ex)...)
	}
	for _, name := range names {
		s := secs[name]
		if !allowIsCompanion(name, s) {
			continue
		}
		orig := strings.TrimSuffix(name, allowCompanionSuffix)
		keep := false
		if o, ok := secs[orig]; ok && o.Type == "rule" && !allowAnonymous(orig) {
			if _, fam, ok := allowSetOf(o); ok && fam == 4 {
				if f, err := allowSectionFamily(o); err == nil && f == 0 {
					keep = true
				}
			}
		}
		if !keep {
			ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + name}})
		}
	}
	return ops
}

// allowAttachOps ties rule section (as parsed in secs) to list id.
func allowAttachOps(secs map[string]uciSection, section, id string) (ops []executor.Op, sets []string, err error) {
	s, ok := secs[section]
	if !ok {
		return nil, nil, fmt.Errorf("rule %s not found", section)
	}
	fam, err := allowSectionFamily(s)
	if err != nil {
		return nil, nil, err
	}
	if fam != 0 || s.Type != "rule" {
		set := allowSetName(id, fam)
		ops = append(ops, setOp("firewall."+section+".ipset", set))
		// It might have had a twin from when it answered both families.
		if c, ok := secs[section+allowCompanionSuffix]; ok && allowIsCompanion(section+allowCompanionSuffix, c) {
			ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + section + allowCompanionSuffix}})
		}
		return ops, []string{set}, nil
	}
	target := section
	if allowAnonymous(section) {
		target = "ngal_" + allowRandName()
		if _, taken := secs[target]; taken {
			return nil, nil, errors.New("could not name the rule, try again")
		}
		ops = append(ops, executor.Op{Kind: "uci_rename", Args: []string{"firewall." + section, target}})
	}
	v4 := allowSetName(id, 4)
	ops = append(ops, setOp("firewall."+target+".ipset", v4))
	o := uciSection{Type: s.Type, Options: map[string][]string{}}
	for k, v := range s.Options {
		o.Options[k] = v
	}
	o.Options["ipset"] = []string{v4}
	c := target + allowCompanionSuffix
	var ex *uciSection
	if cs, ok := secs[c]; ok {
		ex = &cs
	}
	ops = append(ops, allowCompanionOps(c, o, id, ex)...)
	return ops, []string{v4, allowSetName(id, 6)}, nil
}

// allowDetachOps unties a rule from whatever set limits it.
func allowDetachOps(secs map[string]uciSection, section string) []executor.Op {
	ops := []executor.Op{{Kind: "uci_delete", Args: []string{"firewall." + section + ".ipset"}}}
	if c, ok := secs[section+allowCompanionSuffix]; ok && allowIsCompanion(section+allowCompanionSuffix, c) {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + section + allowCompanionSuffix}})
	}
	return ops
}

// ---- which rules ----

// fwdRuleOf reads one rule or forward the way the port forwarding page
// lists it; ok is false for the ones it does not list (not from the
// Internet, not a port, disabled, the firmware's own, NetGrip's IPv6
// twins).
func fwdRuleOf(section string, s uciSection, wanZones, stock map[string]bool, secs map[string]uciSection, names map[string]string) (FwdRule, bool) {
	join := func(k string) string { return strings.Join(s.Options[k], " ") }
	if s.Option("enabled") == "0" || !wanZones[s.Option("src")] {
		return FwdRule{}, false
	}
	switch s.Type {
	case "redirect":
		if t := s.Option("target"); t != "" && t != "DNAT" {
			return FwdRule{}, false
		}
		af := allowedFromOf(section, s, secs, names)
		return FwdRule{
			Section: section, Name: s.Option("name"), SrcDport: join("src_dport"),
			DestIP: s.Option("dest_ip"), DestPort: join("dest_port"), Proto: join("proto"),
			Kind: "forward", Managed: reFwdSection.MatchString(section), AllowedFrom: &af,
		}, true
	case "rule":
		if s.Option("target") != "ACCEPT" || s.Option("dest") != "" || allowIsCompanion(section, s) {
			return FwdRule{}, false
		}
		port := join("dest_port")
		if port == "" || stock[s.Option("name")] {
			return FwdRule{}, false
		}
		af := allowedFromOf(section, s, secs, names)
		return FwdRule{
			Section: section, Name: s.Option("name"), SrcDport: port, Proto: join("proto"),
			Kind: "input", Managed: reFwdSection.MatchString(section), AllowedFrom: &af,
		}, true
	}
	return FwdRule{}, false
}

// allowListNames maps list ids to their names.
func allowListNames() map[string]string {
	allowMu.Lock()
	defer allowMu.Unlock()
	allowLoadLocked()
	out := map[string]string{}
	for _, l := range allowData.Lists {
		out[l.ID] = l.Name
	}
	return out
}

// allowUsers lists the rules (as the page shows them) using list id.
func allowUsers(rules []FwdRule, id string) []FwdRule {
	var out []FwdRule
	for _, r := range rules {
		if r.AllowedFrom != nil && r.AllowedFrom.Kind == "list" && r.AllowedFrom.List == id {
			out = append(out, r)
		}
	}
	return out
}

// allowReferences lists every section whose ipset names set (in use or
// not, listed or not): what deleting the set would break.
func allowReferences(secs map[string]uciSection, sets ...string) []string {
	want := map[string]bool{}
	for _, s := range sets {
		want[s] = true
	}
	var out []string
	for name, s := range secs {
		if s.Type == "ipset" {
			continue
		}
		if f := strings.Fields(s.Option("ipset")); len(f) > 0 && want[strings.TrimPrefix(f[0], "!")] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---- applying ----

// AllowNeedsForce is a change refused until the user confirms it, with
// the reason to show them.
type AllowNeedsForce struct{ Reason string }

func (e *AllowNeedsForce) Error() string { return e.Reason }

// allowApplyFirewall runs ops, commits, reloads the firewall and checks the
// result; anything wrong puts the config back as it was.
func allowApplyFirewall(ops []executor.Op, verify func(map[string]uciSection) error) (rolledBack bool, err error) {
	snap, err := allowSnapshotFn("firewall")
	if err != nil {
		return false, fmt.Errorf("snapshot firewall: %w", err)
	}
	rollback := func() {
		_ = allowRestoreFn("firewall", snap)
		_ = allowRunFn(executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}})
		InvalidateKey("ucishow|firewall")
		InvalidateKey("portforward")
	}
	all := append(append([]executor.Op{}, ops...),
		executor.Op{Kind: "uci_commit", Args: []string{"firewall"}},
		executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}})
	if err := allowApplyFn(all, nil); err != nil {
		rollback()
		return true, err
	}
	InvalidateKey("ucishow|firewall")
	InvalidateKey("portforward")
	if verify != nil {
		if err := verify(allowSections()); err != nil {
			rollback()
			return true, fmt.Errorf("%w; the previous firewall configuration was restored", err)
		}
	}
	return false, nil
}

// allowVerifyRunning checks that the running firewall has the sets, each
// used by a rule.
func allowVerifyRunning(sets []string) error {
	ruleset, err := allowRulesetFn()
	if err != nil {
		return fmt.Errorf("could not read the running firewall: %w", err)
	}
	for _, set := range sets {
		if _, err := allowNftListFn(set); err != nil {
			return fmt.Errorf("the firewall did not create the set %s", set)
		}
		if !strings.Contains(ruleset, "@"+set+" ") {
			return fmt.Errorf("the firewall left out the rule using %s", set)
		}
	}
	return nil
}

// allowWriteListFiles writes a list's set files so a reload fills the sets
// with what they must hold. Called with allowMu held.
func allowWriteListFilesLocked(l AllowList) (v4, v6 []string) {
	v4, v6 = allowElements(l, allowHosts, allowNow())
	for fam, elems := range map[int][]string{4: v4, 6: v6} {
		set := allowSetName(l.ID, fam)
		if err := allowWriteLoadfile(set, allowSetContent(elems)); err != nil {
			log.Printf("allowlists: write %s: %v", set, err)
		}
	}
	return v4, v6
}

// allowMarkApplied records that a reload just filled the sets from their
// files.
func allowMarkAppliedLocked(id string, v4, v6 []string) {
	allowApplied[allowSetName(id, 4)] = allowSetContent(v4)
	allowApplied[allowSetName(id, 6)] = allowSetContent(v6)
}

// ---- the requester ----

// AllowRequesterLocal: the panel is used from one of the router's own
// networks (not through the Internet). Unknown counts as not local.
func AllowRequesterLocal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() {
		return true
	}
	if a.Is6() {
		return a.IsLinkLocalUnicast() || netip.MustParsePrefix("fc00::/7").Contains(a)
	}
	wan := allowInternetNetworks()
	for _, s := range clientSubnetsFn() {
		if wan[s.Interface] || s.Mask < 1 || s.Mask > 30 {
			continue
		}
		base, err := netip.ParseAddr(s.Address)
		if err != nil {
			continue
		}
		if netip.PrefixFrom(base, s.Mask).Masked().Contains(a) {
			return true
		}
	}
	return false
}

// allowInternetNetworks: the interfaces of the zones that face the Internet.
func allowInternetNetworks() map[string]bool {
	out := map[string]bool{ubus.ActiveWANInterfaceName(): true}
	zones := internetZones()
	show, ok := uciShowCached("firewall")
	if !ok {
		return out
	}
	for _, s := range parseUCIShow(show, "firewall") {
		if s.Type == "zone" && zones[s.Option("name")] {
			for _, v := range s.Options["network"] {
				for _, n := range strings.Fields(v) {
					out[n] = true
				}
			}
		}
	}
	return out
}

// ---- sets NetGrip does not manage ----

// AllowExternal is a firewall set something else fills, and what taking it
// over would involve.
type AllowExternal struct {
	Set      string       `json:"set"`
	Family   int          `json:"family"`
	Elements []string     `json:"elements"`
	UsedBy   []FwdRule    `json:"used_by"`
	Writers  []string     `json:"writers"`
	Manage   bool         `json:"can_take_over"`
	Why      string       `json:"why,omitempty"`
	Suggest  []AllowEntry `json:"suggest,omitempty"`
}

// allowExternalSets lists the address sets in the firewall config that are
// not NetGrip's lists.
func allowExternalSets(secs map[string]uciSection, rules []FwdRule) []AllowExternal {
	var out []AllowExternal
	for _, s := range secs {
		name := s.Option("name")
		if s.Type != "ipset" || name == "" || reAllowSet.MatchString(name) || s.Option("enabled") == "0" {
			continue
		}
		e := AllowExternal{Set: name, Family: 4, Elements: []string{}, UsedBy: []FwdRule{}, Writers: []string{}}
		if f := strings.ToLower(s.Option("family")); f == "ipv6" || f == "6" {
			e.Family = 6
		}
		ipOnly := len(s.Options["match"]) > 0
		for _, m := range s.Options["match"] {
			t := m
			if i := strings.LastIndex(m, "_"); i >= 0 {
				t = m[i+1:]
			}
			if t != "ip" && t != "net" {
				ipOnly = false
			}
		}
		listed := map[string]bool{}
		for _, r := range rules {
			if r.AllowedFrom != nil && r.AllowedFrom.Kind == "other" && r.AllowedFrom.Set == name {
				e.UsedBy = append(e.UsedBy, r)
				listed[r.Section] = true
				if r.AllowedFrom.Negated {
					e.Why = fmt.Sprintf("%q uses it to block, not to allow", r.Name)
				}
			}
		}
		for _, ref := range allowReferences(secs, name) {
			if !listed[ref] && e.Why == "" {
				e.Why = "it is also used by a rule that is not a port open to the Internet"
			}
		}
		switch {
		case !ipOnly && e.Why == "":
			e.Why = "it holds something other than addresses"
		case len(e.UsedBy) == 0 && e.Why == "":
			e.Why = "no port open to the Internet uses it"
		}
		e.Manage = e.Why == ""
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Set < out[j].Set })
	return out
}

// parseNftElements reads the addresses out of `nft list set` text.
func parseNftElements(text string) []string {
	i := strings.Index(text, "elements = {")
	if i < 0 {
		return []string{}
	}
	body := text[i+len("elements = {"):]
	if j := strings.Index(body, "}"); j >= 0 {
		body = body[:j]
	}
	out := []string{}
	for _, f := range strings.Split(body, ",") {
		f = strings.TrimSpace(f)
		if sp := strings.IndexAny(f, " \t\n"); sp >= 0 {
			f = f[:sp] // "1.2.3.4 timeout 1h expires ..."
		}
		if f == "" {
			continue
		}
		if _, err := parseAddrOrPrefix(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}

// allowCronWriters finds the scheduled jobs that fill set: a crontab line
// naming it, or running a script that does.
func allowCronWriters(set string) []allowCronLine {
	var out []allowCronLine
	entries, _ := os.ReadDir(allowCrontabDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(allowCrontabDir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			fields := strings.Fields(t)
			if len(fields) < 6 {
				continue
			}
			cmd := strings.Join(fields[5:], " ")
			hit := allowMentions(cmd, set)
			script := ""
			for _, tok := range fields[5:] {
				if strings.HasPrefix(tok, "/") && !hit {
					if b := allowReadSmall(tok); b != nil && allowMentions(string(b), set) {
						hit, script = true, tok
					}
				}
			}
			if hit {
				out = append(out, allowCronLine{File: path, Line: n, Text: line, Script: script})
			}
		}
		f.Close()
	}
	return out
}

type allowCronLine struct {
	File   string
	Line   int
	Text   string
	Script string
}

// allowMentions: s names set as a word (web_allowed, not web_allowed2).
func allowMentions(s, set string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], set)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || !isWordByte(s[j-1])
		after := j+len(set) >= len(s) || !isWordByte(s[j+len(set)])
		if before && after {
			return true
		}
		i = j + 1
	}
}

func isWordByte(c byte) bool {
	return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// allowReadSmall reads a regular file of at most 64 KiB, or nil.
func allowReadSmall(path string) []byte {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

var reHostToken = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,63}`)

// allowHostCandidates pulls the host names out of a script.
func allowHostCandidates(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reHostToken.FindAllString(text, -1) {
		h, ok := allowHostname(m)
		if !ok || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// allowDisableCronLines comments out the given crontab lines, keeping them
// readable, and restarts cron when a file changed.
func allowDisableCronLines(lines []allowCronLine, listName string) error {
	byFile := map[string]map[int]bool{}
	for _, l := range lines {
		if byFile[l.File] == nil {
			byFile[l.File] = map[int]bool{}
		}
		byFile[l.File][l.Line] = true
	}
	changed := false
	for file, nums := range byFile {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		st, _ := os.Stat(file)
		rows := strings.Split(string(b), "\n")
		for i := range rows {
			if nums[i+1] && !strings.HasPrefix(strings.TrimSpace(rows[i]), "#") {
				rows[i] = fmt.Sprintf("# netgrip allowlists: replaced by the list %q: %s", listName, rows[i])
				changed = true
			}
		}
		if err := writeFileAtomic(file, []byte(strings.Join(rows, "\n"))); err != nil {
			return err
		}
		if st != nil {
			_ = os.Chmod(file, st.Mode().Perm())
		}
	}
	if changed {
		if _, err := os.Stat("/etc/init.d/cron"); err == nil {
			return allowRunFn(executor.Op{Kind: "initd", Args: []string{"cron", "restart"}})
		}
	}
	return nil
}
