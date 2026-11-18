package modules

// Allow lists: named lists of addresses, address ranges and host names (a
// dynamic DNS name, say) that a port open to the Internet can be limited
// to. A list becomes two firewall sets, one per address family
// (netgrip_allow_<id>_v4 and _v6), and a port forward or a port open on
// the router is limited to it with fw4's own "ipset" option. Everything
// about it fails closed:
//
//   - fw4 drops a rule whose set is missing or disabled outright, so a
//     rule tied to a list never falls back to "anyone";
//   - an empty list matches nobody;
//   - a name that no longer exists is dropped at once; a name that cannot
//     be looked up (DNS down) keeps its last address only for the time the
//     list allows, then is dropped too.
//
// Where things live, and why:
//
//   - The lists themselves (names, entries, notes) are in
//     /etc/netgrip/allowlists.json, written only when they are edited.
//   - What goes into each set (the fixed entries plus what the names
//     resolve to) is in a file on tmpfs that fw4 loads on every reload
//     (the set's "loadfile"), and is put into the running set in one nft
//     transaction when it changes. Nothing is written to flash when an
//     address changes, and a firewall reload (by NetGrip, LuCI or a
//     hotplug event) keeps the addresses. After a reboot the sets are empty
//     until NetGrip has filled them, seconds after it starts: closed, not
//     open.
//   - Which rule uses which list is the rule's own "ipset" option: there is
//     no second record of it to get out of step.
//
// Names are looked up by NetGrip itself (no command is run), every two
// minutes, through the router's resolver; nft runs only when a set's
// content changed, and once every ten minutes to repair a set something
// else emptied.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	allowSetPrefix       = "netgrip_allow_"
	allowMaxLists        = 32
	allowMaxEntries      = 64
	allowMaxHosts        = 128 // names across all lists
	allowMaxAddrsPerHost = 16
	allowNameMax         = 40
	allowNoteMax         = 64
	allowLookupTimeout   = 4 * time.Second
	allowLookupWorkers   = 8
	allowTickEvery       = 2 * time.Minute
	allowTickRetry       = 20 * time.Second // while a name was never resolved
	allowRepairEvery     = 5                // ticks between unconditional set refills
)

// allowKeepChoices are the times a name's last address is kept while it
// cannot be looked up. 0: dropped at once.
var allowKeepChoices = map[int]bool{0: true, 1: true, 6: true, 24: true}

// Paths and seams (tests point them elsewhere).
var (
	allowStorePath = "/etc/netgrip/allowlists.json"
	allowRunDir    = "/var/run/netgrip-allowlists"
	// network is "ip4" or "ip6": each family is looked up on its own, so a
	// timeout in one does not drop the other's addresses. The name is
	// queried as absolute (a trailing dot): the resolver's search domain
	// ("lan") is never tried.
	allowLookupFn = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	allowNftFn = func(script string) error {
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	allowNow = time.Now
)

var (
	reAllowSet = regexp.MustCompile(`^` + allowSetPrefix + `([a-z0-9]{1,12})_v([46])$`)
	reAllowID  = regexp.MustCompile(`^[a-z0-9]{1,12}$`)
)

// AllowEntry is one line of a list: an address, a range or a host name.
type AllowEntry struct {
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// AllowList is a named list.
type AllowList struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// KeepHours: how long a name's last address is kept while the name
	// cannot be looked up (see allowKeepChoices).
	KeepHours int          `json:"keep_hours"`
	Entries   []AllowEntry `json:"entries"`
}

type allowStore struct {
	Lists []AllowList `json:"lists"`
}

// allowFam is what one name resolves to in one family.
type allowFam struct {
	Addrs []netip.Addr `json:"addrs,omitempty"` // last good answer
	OKAt  time.Time    `json:"ok_at,omitzero"`
	Err   string       `json:"err,omitempty"`
	// NotFound: the family has no address for the name (it does not exist,
	// has no record of this family, or points only at an address a list
	// cannot hold, the way a parked dynamic DNS name points at 0.0.0.0).
	NotFound bool `json:"not_found,omitempty"`
}

// allowHost is what NetGrip knows about one name.
type allowHost struct {
	V4        allowFam  `json:"v4"`
	V6        allowFam  `json:"v6"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
}

var (
	allowMu      sync.Mutex
	allowLoaded  bool
	allowData    allowStore
	allowHosts   = map[string]*allowHost{}
	allowApplied = map[string]string{} // set -> content last put into nft
	allowSetErr  = map[string]string{} // set -> why the running set could not be refilled
)

// ---- entries ----

// allowEntryKind classifies a value: "ip", "net" or "host". The prefix is
// set for "ip" (a single address) and "net"; the name for "host".
func allowEntryKind(v string) (kind string, p netip.Prefix, host string, err error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", p, "", errors.New("empty entry")
	}
	if strings.Contains(v, "/") {
		p, err = netip.ParsePrefix(v)
		if err != nil {
			return "", p, "", fmt.Errorf("%q is not a valid address range", v)
		}
		if p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return "", p, "", fmt.Errorf("%q is not a valid address range", v)
		}
		p = p.Masked()
		// A very wide range lets a large part of the Internet in: not an
		// allow list any more.
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			return "", p, "", fmt.Errorf("%q is too wide: it would let a large part of the Internet in", v)
		}
		if bad := allowBadAddr(p.Addr()); bad != "" {
			return "", p, "", fmt.Errorf("%q is %s", v, bad)
		}
		if p.IsSingleIP() {
			return "ip", p, "", nil
		}
		return "net", p, "", nil
	}
	if a, perr := netip.ParseAddr(v); perr == nil {
		if a.Zone() != "" {
			return "", p, "", fmt.Errorf("%q: an address with a zone cannot be used", v)
		}
		a = a.Unmap()
		if bad := allowBadAddr(a); bad != "" {
			return "", p, "", fmt.Errorf("%q is %s", v, bad)
		}
		return "ip", netip.PrefixFrom(a, a.BitLen()), "", nil
	}
	if h, ok := allowHostname(v); ok {
		return "host", p, h, nil
	}
	return "", p, "", fmt.Errorf("%q is not an address, a range (198.51.100.0/24) or a host name", v)
}

// allowBadAddr names why an address cannot be in a list, or "".
func allowBadAddr(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "the unspecified address"
	case a.IsLoopback():
		return "a loopback address"
	case a.IsMulticast():
		return "a multicast address"
	case a.IsLinkLocalUnicast():
		return "a link-local address"
	}
	return ""
}

// allowHostname reports whether s is a usable DNS name, lower-cased and
// without a trailing dot: labels of letters, digits and hyphens, at least
// two of them, the last not all digits.
func allowHostname(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" {
		return "", false
	}
	return s, true
}

// allowCleanText drops control and invisible characters and bounds the
// length of a name or a note.
func allowCleanText(s string, max int) string {
	if !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if utf8.RuneCountInString(out) > max {
		out = strings.TrimSpace(string([]rune(out)[:max]))
	}
	return out
}

// allowValidate checks and normalises a list as the user sent it.
func allowValidate(l AllowList) (AllowList, error) {
	l.Name = allowCleanText(l.Name, allowNameMax)
	if l.Name == "" {
		return l, errors.New("the list needs a name")
	}
	if !allowKeepChoices[l.KeepHours] {
		return l, fmt.Errorf("keep_hours must be 0, 1, 6 or 24")
	}
	if len(l.Entries) > allowMaxEntries {
		return l, fmt.Errorf("a list holds at most %d entries", allowMaxEntries)
	}
	seen := map[string]bool{}
	out := make([]AllowEntry, 0, len(l.Entries))
	for _, e := range l.Entries {
		kind, p, host, err := allowEntryKind(e.Value)
		if err != nil {
			return l, err
		}
		v := host
		if kind != "host" {
			v = p.String()
			if kind == "ip" {
				v = p.Addr().String()
			}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, AllowEntry{Value: v, Note: allowCleanText(e.Note, allowNoteMax)})
	}
	l.Entries = out
	return l, nil
}

// allowNewID makes a list id from its name: lower-case letters and digits,
// unique among taken.
func allowNewID(name string, taken map[string]bool) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z' || r >= '0' && r <= '9') && b.Len() < 10 {
			b.WriteRune(r)
		}
	}
	base := b.String()
	if base == "" {
		base = "list"
	}
	if !taken[base] {
		return base
	}
	for i := 2; i < 1000; i++ {
		id := fmt.Sprintf("%s%d", base, i)
		if len(id) > 12 {
			id = id[len(id)-12:]
		}
		if !taken[id] && reAllowID.MatchString(id) {
			return id
		}
	}
	return fmt.Sprintf("l%d", allowNow().UnixNano()%1e10)
}

// ---- sets ----

// allowSetName is the firewall set of a list for a family (4 or 6).
func allowSetName(id string, family int) string {
	return fmt.Sprintf("%s%s_v%d", allowSetPrefix, id, family)
}

// allowLoadfile is where a set's addresses are kept for fw4 (tmpfs).
func allowLoadfile(set string) string {
	return filepath.Join(allowRunDir, set+".txt")
}

// allowNormalize sorts prefixes and drops any that another one already
// covers. Prefixes are either nested or disjoint, so what is left never
// overlaps.
func allowNormalize(ps []netip.Prefix) []netip.Prefix {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, k := range out {
			if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// allowElemString is how a set element is written: a plain address for a
// single one, the range otherwise.
func allowElemString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// allowHostAddrs is what a name contributes to a list now, per family: its
// last answer, or, while that family cannot be looked up, the last good one
// for as long as the list keeps it. A family the name has no address in
// contributes nothing.
func allowHostAddrs(h *allowHost, keepHours int, now time.Time) []netip.Addr {
	if h == nil {
		return nil
	}
	return append(allowFamAddrs(h.V4, keepHours, now), allowFamAddrs(h.V6, keepHours, now)...)
}

func allowFamAddrs(f allowFam, keepHours int, now time.Time) []netip.Addr {
	if f.NotFound || len(f.Addrs) == 0 {
		return nil
	}
	if f.Err == "" {
		return f.Addrs
	}
	if keepHours > 0 && now.Sub(f.OKAt) <= time.Duration(keepHours)*time.Hour {
		return f.Addrs
	}
	return nil
}

// allowHostStatus sums a name up for the page: an error to show, and
// whether addresses are kept from an earlier answer.
func allowHostStatus(h *allowHost, keepHours int, now time.Time) (errText string, stale bool) {
	if h == nil {
		return "", false
	}
	if h.V4.NotFound && h.V6.NotFound {
		return "the name does not exist or has no usable address", false
	}
	for _, f := range []allowFam{h.V4, h.V6} {
		if f.Err != "" {
			errText = f.Err
			if len(allowFamAddrs(f, keepHours, now)) > 0 {
				stale = true
			}
		}
	}
	return errText, stale
}

// allowElements is what each of a list's two sets should hold.
func allowElements(l AllowList, hosts map[string]*allowHost, now time.Time) (v4, v6 []string) {
	var p4, p6 []netip.Prefix
	add := func(p netip.Prefix) {
		if p.Addr().Is4() {
			p4 = append(p4, p)
		} else {
			p6 = append(p6, p)
		}
	}
	for _, e := range l.Entries {
		kind, p, host, err := allowEntryKind(e.Value)
		if err != nil {
			continue
		}
		if kind != "host" {
			add(p)
			continue
		}
		for _, a := range allowHostAddrs(hosts[host], l.KeepHours, now) {
			add(netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, p := range allowNormalize(p4) {
		v4 = append(v4, allowElemString(p))
	}
	for _, p := range allowNormalize(p6) {
		v6 = append(v6, allowElemString(p))
	}
	return v4, v6
}

// allowCovers reports whether addr (an address or a range) lies inside one
// of elems.
func allowCovers(elems []string, addr string) bool {
	var q netip.Prefix
	if p, err := netip.ParsePrefix(addr); err == nil {
		q = p.Masked()
	} else if a, err := netip.ParseAddr(addr); err == nil {
		a = a.Unmap()
		q = netip.PrefixFrom(a, a.BitLen())
	} else {
		return false
	}
	for _, e := range elems {
		var p netip.Prefix
		if strings.Contains(e, "/") {
			p, _ = netip.ParsePrefix(e)
		} else if a, err := netip.ParseAddr(e); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.IsValid() && p.Bits() <= q.Bits() && p.Contains(q.Addr()) {
			return true
		}
	}
	return false
}

// allowSetScript is the nft transaction that makes a running set hold
// exactly elems: emptied and refilled at once, so no packet ever sees it
// half done, and a failure leaves it as it was.
func allowSetScript(set string, elems []string) string {
	s := "flush set inet fw4 " + set + "\n"
	if len(elems) > 0 {
		s += "add element inet fw4 " + set + " { " + strings.Join(elems, ", ") + " }\n"
	}
	return s
}

// allowSetContent is what the loadfile holds (and the comparison key): one
// element per line, nothing else (no comment line: not every fw4 skips
// them).
func allowSetContent(elems []string) string {
	if len(elems) == 0 {
		return ""
	}
	return strings.Join(elems, "\n") + "\n"
}

// allowWriteLoadfile writes a set's file if it changed. tmpfs: no flash.
func allowWriteLoadfile(set, content string) error {
	path := allowLoadfile(set)
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return nil
	}
	if err := os.MkdirAll(allowRunDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(content))
}

// allowPushSet writes a set's file and, when the set is in use (exists in
// the firewall config) and its content changed or force is set, refills the
// running set. Called with allowMu held.
func allowPushSet(set string, elems []string, inConfig, force bool) {
	content := allowSetContent(elems)
	if err := allowWriteLoadfile(set, content); err != nil {
		log.Printf("allowlists: write %s: %v", set, err)
	}
	if !inConfig {
		delete(allowApplied, set)
		return
	}
	if !force && allowApplied[set] == content {
		return
	}
	if err := allowNftFn(allowSetScript(set, elems)); err != nil {
		// Not refilled: the running set may still hold an address that was
		// just removed. Empty it instead (closed, not open); the next tick
		// tries again. A set the running firewall does not have yet makes
		// this fail too, harmlessly: the next reload fills it from the file.
		_ = allowNftFn(allowSetScript(set, nil))
		if allowSetErr[set] == "" {
			log.Printf("allowlists: refill %s: %v", set, err)
		}
		allowSetErr[set] = allowCleanText(err.Error(), 120)
		delete(allowApplied, set)
		return
	}
	delete(allowSetErr, set)
	allowApplied[set] = content
}

// ---- store ----

func allowLoadLocked() {
	if allowLoaded {
		return
	}
	allowLoaded = true
	allowData = allowStore{}
	if b, err := os.ReadFile(allowStorePath); err == nil {
		var s allowStore
		if json.Unmarshal(b, &s) == nil {
			for _, l := range s.Lists {
				if !reAllowID.MatchString(l.ID) {
					continue
				}
				if v, err := allowValidate(l); err == nil {
					allowData.Lists = append(allowData.Lists, v)
				}
			}
		} else {
			log.Printf("allowlists: %s is not valid JSON, ignored", allowStorePath)
		}
	}
	// What the names resolved to before a restart of NetGrip (not of the
	// router: tmpfs).
	if b, err := os.ReadFile(filepath.Join(allowRunDir, "hosts.json")); err == nil {
		var h map[string]*allowHost
		if json.Unmarshal(b, &h) == nil {
			for k, v := range h {
				if v != nil {
					allowHosts[k] = v
				}
			}
		}
	}
}

func allowSaveLocked() error {
	b, err := json.MarshalIndent(allowData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(allowStorePath), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(allowStorePath, b); err != nil {
		return err
	}
	return os.Chmod(allowStorePath, 0o600)
}

func allowSaveHostsLocked() {
	b, err := json.Marshal(allowHosts)
	if err != nil {
		return
	}
	if os.MkdirAll(allowRunDir, 0o700) == nil {
		_ = writeFileAtomic(filepath.Join(allowRunDir, "hosts.json"), b)
	}
}

func allowFindLocked(id string) (int, *AllowList) {
	for i := range allowData.Lists {
		if allowData.Lists[i].ID == id {
			return i, &allowData.Lists[i]
		}
	}
	return -1, nil
}

// ---- names ----

// allowHostsOf lists the names of some lists, each once.
func allowHostsOf(lists []AllowList) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, e := range l.Entries {
			if kind, _, host, err := allowEntryKind(e.Value); err == nil && kind == "host" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	return out
}

// allowLookup resolves names in parallel (bounded), each family on its
// own, without any lock held.
func allowLookup(hosts []string) map[string]allowLookupResult {
	out := make(map[string]allowLookupResult, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, allowLookupWorkers)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := allowLookupResult{v4: allowLookupFam(h, "ip4"), v6: allowLookupFam(h, "ip6")}
			mu.Lock()
			out[h] = r
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return out
}

type allowFamResult struct {
	addrs    []netip.Addr
	err      error
	notFound bool
}

type allowLookupResult struct {
	v4, v6 allowFamResult
}

func allowLookupFam(host, network string) allowFamResult {
	ctx, cancel := context.WithTimeout(context.Background(), allowLookupTimeout)
	addrs, err := allowLookupFn(ctx, network, host+".")
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		return allowFamResult{err: err, notFound: errors.As(err, &dnsErr) && dnsErr.IsNotFound}
	}
	var keep []netip.Addr
	for _, a := range allowUsableAddrs(addrs) {
		if a.Is4() == (network == "ip4") {
			keep = append(keep, a)
		}
	}
	// Only addresses a list cannot hold (0.0.0.0, 127.0.0.1: a parked
	// dynamic DNS name, a sinkhole): the name points nowhere usable. Gone,
	// not "failing": its old address may belong to someone else by now.
	if len(keep) == 0 {
		return allowFamResult{notFound: true}
	}
	return allowFamResult{addrs: keep}
}

// allowUsableAddrs keeps the addresses a list may hold, each once, at most
// allowMaxAddrsPerHost, sorted.
func allowUsableAddrs(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || allowBadAddr(a) != "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	if len(out) > allowMaxAddrsPerHost {
		out = out[:allowMaxAddrsPerHost]
	}
	return out
}

// allowRecordFam folds one family's answer into what is known.
func allowRecordFam(f *allowFam, r allowFamResult, now time.Time) bool {
	switch {
	case r.err == nil && !r.notFound:
		if f.Err == "" && !f.NotFound && !f.OKAt.IsZero() && addrsEqual(f.Addrs, r.addrs) {
			f.OKAt = now
			return false
		}
		f.Addrs, f.OKAt, f.Err, f.NotFound = r.addrs, now, "", false
	case r.notFound:
		if f.NotFound && len(f.Addrs) == 0 {
			return false
		}
		f.Addrs, f.Err, f.NotFound = nil, "", true
	default:
		f.Err, f.NotFound = allowShortErr(r.err), false
	}
	return true
}

// allowRecordLocked stores lookup results.
func allowRecordLocked(res map[string]allowLookupResult, now time.Time) {
	changed := false
	for h, r := range res {
		st := allowHosts[h]
		if st == nil {
			st = &allowHost{}
			allowHosts[h] = st
		}
		st.CheckedAt = now
		if allowRecordFam(&st.V4, r.v4, now) {
			changed = true
		}
		if allowRecordFam(&st.V6, r.v6, now) {
			changed = true
		}
	}
	// Forget names no list has any more.
	inUse := map[string]bool{}
	for _, h := range allowHostsOf(allowData.Lists) {
		inUse[h] = true
	}
	for h := range allowHosts {
		if !inUse[h] {
			delete(allowHosts, h)
			changed = true
		}
	}
	if changed {
		allowSaveHostsLocked()
	}
}

func addrsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allowShortErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return "the lookup timed out"
		case dnsErr.IsTemporary:
			return "the lookup failed (temporary)"
		}
		return "the lookup failed"
	}
	return allowCleanText(err.Error(), 80)
}

// ---- refresh ----

var (
	allowOnce    sync.Once
	allowTicks   int
	allowStarted time.Time
)

// StartAllowlists keeps the lists' sets filled (see the top of the file).
// With no list it does nothing but wait.
func StartAllowlists() {
	allowOnce.Do(func() {
		go func() {
			allowStarted = time.Now()
			allowRefresh(true)
			for {
				d := allowTickEvery
				if allowNeedsRetry() {
					d = allowTickRetry
				}
				time.Sleep(d)
				allowTicks++
				allowRefresh(allowTicks%allowRepairEvery == 0)
				allowSyncCompanionsTick()
			}
		}()
	})
}

// allowNeedsRetry: in the first minutes after NetGrip started, some name
// was never resolved (the router just booted, DNS not up yet): try again
// sooner. Later, a name that keeps failing waits for the normal tick.
func allowNeedsRetry() bool {
	if time.Since(allowStarted) > 5*time.Minute {
		return false
	}
	allowMu.Lock()
	defer allowMu.Unlock()
	for _, h := range allowHostsOf(allowData.Lists) {
		st := allowHosts[h]
		if st == nil || (st.V4.OKAt.IsZero() && !st.V4.NotFound && st.V6.OKAt.IsZero() && !st.V6.NotFound) {
			return true
		}
	}
	return false
}

// allowRefresh looks the names up and refills every set whose content
// changed (all of them with force).
func allowRefresh(force bool) {
	if !allowSupported() {
		return
	}
	allowMu.Lock()
	allowLoadLocked()
	if len(allowData.Lists) == 0 {
		allowMu.Unlock()
		return
	}
	hosts := allowHostsOf(allowData.Lists)
	allowMu.Unlock()

	var extra []string
	if len(hosts) > allowMaxHosts {
		hosts, extra = hosts[:allowMaxHosts], hosts[allowMaxHosts:]
	}
	res := allowLookup(hosts)
	// Names past the cap (only a hand-edited file can have them) count as
	// failing, so whatever they had runs out like any failing name.
	tooMany := allowFamResult{err: errors.New("too many host names")}
	for _, h := range extra {
		res[h] = allowLookupResult{v4: tooMany, v6: tooMany}
	}

	inConfig := allowSetsInConfig()
	allowMu.Lock()
	defer allowMu.Unlock()
	now := allowNow()
	allowRecordLocked(res, now)
	for _, l := range allowData.Lists {
		v4, v6 := allowElements(l, allowHosts, now)
		allowPushSet(allowSetName(l.ID, 4), v4, inConfig[allowSetName(l.ID, 4)], force)
		allowPushSet(allowSetName(l.ID, 6), v6, inConfig[allowSetName(l.ID, 6)], force)
	}
}

// allowRefreshList looks up one list's names now and refills its sets (an
// edit: the page shows what the names resolve to at once).
func allowRefreshList(id string) {
	allowMu.Lock()
	_, l := allowFindLocked(id)
	if l == nil {
		allowMu.Unlock()
		return
	}
	hosts := allowHostsOf([]AllowList{*l})
	allowMu.Unlock()

	res := allowLookup(hosts)
	inConfig := allowSetsInConfig()

	allowMu.Lock()
	defer allowMu.Unlock()
	now := allowNow()
	allowRecordLocked(res, now)
	if _, l = allowFindLocked(id); l != nil {
		v4, v6 := allowElements(*l, allowHosts, now)
		allowPushSet(allowSetName(id, 4), v4, inConfig[allowSetName(id, 4)], false)
		allowPushSet(allowSetName(id, 6), v6, inConfig[allowSetName(id, 6)], false)
	}
}

// allowSupported: fw4 (nftables) with set files ("loadfile") is what this
// feature is built on. fw3 (OpenWrt 21.02 and older), or an fw4 too old to
// load a set from a file, is not supported. Read once.
var allowSupported = func() bool {
	allowSupportedOnce.Do(func() {
		b, err := os.ReadFile("/usr/share/ucode/fw4.uc")
		if err != nil || !strings.Contains(string(b), "loadfile") {
			return
		}
		_, err = exec.LookPath("nft")
		allowSupportedVal = err == nil
	})
	return allowSupportedVal
}

var (
	allowSupportedOnce sync.Once
	allowSupportedVal  bool
)

// allowSetsInConfig: the list sets that exist in the firewall config.
func allowSetsInConfig() map[string]bool {
	out := map[string]bool{}
	show, ok := uciShowCached("firewall")
	if !ok {
		return out
	}
	for _, s := range parseUCIShow(show, "firewall") {
		if s.Type == "ipset" && reAllowSet.MatchString(s.Option("name")) {
			out[s.Option("name")] = true
		}
	}
	return out
}
