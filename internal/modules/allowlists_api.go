package modules

// Allow lists: what the panel calls (see allowlists.go for the design).

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/gnacho/netgrip/internal/executor"
)

// AllowEntryView is an entry with what it stands for now.
type AllowEntryView struct {
	Value     string   `json:"value"`
	Note      string   `json:"note,omitempty"`
	Kind      string   `json:"kind"` // ip, net, host
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
	// Stale: the name cannot be looked up now and its last addresses are
	// still kept (see the list's keep_hours).
	Stale     bool  `json:"stale,omitempty"`
	CheckedAt int64 `json:"checked_at,omitempty"`
}

// AllowListView is a list as the page shows it.
type AllowListView struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	KeepHours int              `json:"keep_hours"`
	Entries   []AllowEntryView `json:"entries"`
	V4        []string         `json:"v4"`
	V6        []string         `json:"v6"`
	UsedBy    []FwdRule        `json:"used_by"`
}

// AllowYou is the device using the panel, as the router sees it.
type AllowYou struct {
	IP    string   `json:"ip"`
	Local bool     `json:"local"`
	Lists []string `json:"lists"` // lists that let it in
}

// AllowProbe is the allow lists card.
type AllowProbe struct {
	Supported bool            `json:"supported"`
	Reason    string          `json:"reason,omitempty"`
	Lists     []AllowListView `json:"lists"`
	External  []AllowExternal `json:"external"`
	You       AllowYou        `json:"you"`
	MaxLists  int             `json:"max_lists"`
	MaxItems  int             `json:"max_entries"`
}

// allowUnsupportedReason says why the card cannot be used here, or "".
func allowUnsupportedReason() string {
	if !allowSupported() {
		return "needs firewall4 (nftables): OpenWrt 22.03 or newer"
	}
	if !allowGatewayFn() {
		return "only applies on the gateway (needs WAN and firewall)"
	}
	return ""
}

// allowGatewayFn: the router has an uplink and a firewall (a seam).
var allowGatewayFn = func() bool {
	p := ProbeFwd()
	return p.HasWan && p.Firewall
}

// ProbeAllowlists reads the lists, who uses them and the sets NetGrip
// does not manage.
func ProbeAllowlists(requester string) *AllowProbe {
	p := &AllowProbe{Lists: []AllowListView{}, External: []AllowExternal{},
		MaxLists: allowMaxLists, MaxItems: allowMaxEntries}
	p.You = AllowYou{IP: requester, Local: AllowRequesterLocal(requester), Lists: []string{}}
	if r := allowUnsupportedReason(); r != "" {
		p.Reason = r
		return p
	}
	p.Supported = true
	rules := ProbeFwd().Rules
	allowMu.Lock()
	allowLoadLocked()
	now := allowNow()
	for _, l := range allowData.Lists {
		v := AllowListView{ID: l.ID, Name: l.Name, KeepHours: l.KeepHours, Entries: []AllowEntryView{}, UsedBy: []FwdRule{}}
		for _, e := range l.Entries {
			ev := AllowEntryView{Value: e.Value, Note: e.Note, Addresses: []string{}}
			kind, pfx, host, err := allowEntryKind(e.Value)
			ev.Kind = kind
			if err != nil {
				ev.Error = err.Error()
			} else if kind == "host" {
				st := allowHosts[host]
				for _, a := range allowHostAddrs(st, l.KeepHours, now) {
					ev.Addresses = append(ev.Addresses, a.String())
				}
				if st != nil {
					ev.Error = st.Err
					ev.Stale = st.Err != "" && !st.NotFound && len(ev.Addresses) > 0
					if !st.CheckedAt.IsZero() {
						ev.CheckedAt = st.CheckedAt.Unix()
					}
				}
			} else {
				ev.Addresses = append(ev.Addresses, allowElemString(pfx))
			}
			v.Entries = append(v.Entries, ev)
		}
		v.V4, v.V6 = allowElements(l, allowHosts, now)
		if v.V4 == nil {
			v.V4 = []string{}
		}
		if v.V6 == nil {
			v.V6 = []string{}
		}
		if u := allowUsers(rules, l.ID); u != nil {
			v.UsedBy = u
		}
		if requester != "" && (allowCovers(v.V4, requester) || allowCovers(v.V6, requester)) {
			p.You.Lists = append(p.You.Lists, l.ID)
		}
		p.Lists = append(p.Lists, v)
	}
	allowMu.Unlock()
	for _, e := range allowExternalSets(allowSections(), rules) {
		if out, err := allowNftListFn(e.Set); err == nil {
			e.Elements = parseNftElements(out)
		}
		for _, w := range allowCronWriters(e.Set) {
			e.Writers = append(e.Writers, w.Text)
		}
		p.External = append(p.External, e)
	}
	return p
}

// AllowSaveRequest creates (no id) or replaces a list.
type AllowSaveRequest struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	KeepHours int          `json:"keep_hours"`
	Entries   []AllowEntry `json:"entries"`
	Force     bool         `json:"force"`
}

// allowPreview resolves a list's names without recording anything: what
// its sets would hold.
func allowPreview(l AllowList) (v4, v6 []string) {
	res := allowLookup(allowHostsOf([]AllowList{l}))
	allowMu.Lock()
	hosts := map[string]*allowHost{}
	for h, st := range allowHosts {
		c := *st
		hosts[h] = &c
	}
	allowMu.Unlock()
	now := allowNow()
	for h, r := range res {
		st := hosts[h]
		if st == nil {
			st = &allowHost{}
			hosts[h] = st
		}
		switch {
		case r.err == nil:
			st.Addrs, st.OKAt, st.Err, st.NotFound = r.addrs, now, "", false
		case r.notFound:
			st.Addrs, st.Err, st.NotFound = nil, "not found", true
		default:
			st.Err = "failed"
		}
	}
	return allowElements(l, hosts, now)
}

// AllowSave stores a list and refills its sets. Used from the Internet,
// a change that would leave the requester out of a list in use is
// refused unless forced.
func AllowSave(req AllowSaveRequest, requester string) (*AllowProbe, error) {
	if r := allowUnsupportedReason(); r != "" {
		return ProbeAllowlists(requester), errors.New(r)
	}
	l, err := allowValidate(AllowList{ID: req.ID, Name: req.Name, KeepHours: req.KeepHours, Entries: req.Entries})
	if err != nil {
		return ProbeAllowlists(requester), err
	}
	if n := len(allowHostsOf([]AllowList{l})); n > allowMaxHosts {
		return ProbeAllowlists(requester), fmt.Errorf("too many host names (at most %d)", allowMaxHosts)
	}

	allowMu.Lock()
	allowLoadLocked()
	if req.ID != "" {
		if _, old := allowFindLocked(req.ID); old == nil {
			allowMu.Unlock()
			return ProbeAllowlists(requester), fmt.Errorf("list %s not found", req.ID)
		}
	} else {
		if len(allowData.Lists) >= allowMaxLists {
			allowMu.Unlock()
			return ProbeAllowlists(requester), fmt.Errorf("at most %d lists", allowMaxLists)
		}
		taken := map[string]bool{}
		for _, x := range allowData.Lists {
			taken[x.ID] = true
		}
		l.ID = allowNewID(l.Name, taken)
	}
	total := len(allowHostsOf(append(allowOthersLocked(l.ID), l)))
	allowMu.Unlock()
	if total > allowMaxHosts {
		return ProbeAllowlists(requester), fmt.Errorf("too many host names across all lists (at most %d)", allowMaxHosts)
	}

	// Locked out? Only a list in use matters, and only from outside.
	if req.ID != "" && !req.Force && !AllowRequesterLocal(requester) {
		rules := ProbeFwd().Rules
		if len(allowUsers(rules, req.ID)) > 0 {
			allowMu.Lock()
			_, old := allowFindLocked(req.ID)
			var before4, before6 []string
			if old != nil {
				before4, before6 = allowElements(*old, allowHosts, allowNow())
			}
			allowMu.Unlock()
			after4, after6 := allowPreview(l)
			was := allowCovers(before4, requester) || allowCovers(before6, requester)
			is := allowCovers(after4, requester) || allowCovers(after6, requester)
			if was && !is {
				return ProbeAllowlists(requester), &AllowNeedsForce{Reason: fmt.Sprintf(
					"You are connected from %s, which this change takes out of the list. If you reach the router through a port this list limits, you will lose access.", requester)}
			}
		}
	}

	allowMu.Lock()
	if i, _ := allowFindLocked(l.ID); i >= 0 {
		allowData.Lists[i] = l
	} else {
		allowData.Lists = append(allowData.Lists, l)
	}
	err = allowSaveLocked()
	allowMu.Unlock()
	if err != nil {
		return ProbeAllowlists(requester), fmt.Errorf("save the lists: %w", err)
	}
	allowRefreshList(l.ID)
	InvalidateKey("portforward")
	return ProbeAllowlists(requester), nil
}

func allowOthersLocked(id string) []AllowList {
	var out []AllowList
	for _, x := range allowData.Lists {
		if x.ID != id {
			out = append(out, x)
		}
	}
	return out
}

// AllowDelete removes a list no rule uses.
func AllowDelete(id, requester string) (*AllowProbe, bool, error) {
	fwWriteMu.Lock()
	defer fwWriteMu.Unlock()
	allowMu.Lock()
	allowLoadLocked()
	i, l := allowFindLocked(id)
	allowMu.Unlock()
	if l == nil {
		return ProbeAllowlists(requester), false, fmt.Errorf("list %s not found", id)
	}
	secs := allowSections()
	sets := []string{allowSetName(id, 4), allowSetName(id, 6)}
	if refs := allowReferences(secs, sets...); len(refs) > 0 {
		var names []string
		for _, r := range refs {
			if n := secs[r].Option("name"); n != "" {
				names = append(names, n)
			} else {
				names = append(names, r)
			}
		}
		return ProbeAllowlists(requester), false, fmt.Errorf(
			"the list is still in use by %s: choose who may reach those first", strings.Join(names, ", "))
	}
	var ops []executor.Op
	for _, set := range sets {
		if _, ok := secs[set]; ok {
			ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + set}})
		}
	}
	if len(ops) > 0 {
		if rb, err := allowApplyFirewall(ops, nil); err != nil {
			return ProbeAllowlists(requester), rb, err
		}
	}
	allowMu.Lock()
	if i, _ = allowFindLocked(id); i >= 0 {
		allowData.Lists = append(allowData.Lists[:i], allowData.Lists[i+1:]...)
	}
	err := allowSaveLocked()
	for _, set := range sets {
		delete(allowApplied, set)
		_ = os.Remove(allowLoadfile(set))
	}
	allowRecordLocked(nil, allowNow()) // forget its names
	allowMu.Unlock()
	if err != nil {
		return ProbeAllowlists(requester), false, fmt.Errorf("save the lists: %w", err)
	}
	return ProbeAllowlists(requester), false, nil
}

// AllowUseRequest sets who may reach one rule: a list, or anyone.
type AllowUseRequest struct {
	Section string        `json:"section"`
	List    string        `json:"list"` // "" = anyone
	Expect  *AllowRuleRef `json:"expect,omitempty"`
	// OpenToAnyone must be set to remove a limit: it makes the port
	// reachable from the whole Internet.
	OpenToAnyone bool `json:"open_to_anyone"`
	Force        bool `json:"force"`
}

// allowFindRule finds the rule a request names, checking it is still the
// one the page showed.
func allowFindRule(section string, expect *AllowRuleRef) (FwdRule, error) {
	for _, r := range ProbeFwd().Rules {
		if r.Section != section {
			continue
		}
		if expect != nil && (expect.Name != r.Name || expect.Port != r.SrcDport || expect.Proto != r.Proto || expect.Kind != r.Kind) {
			return r, errors.New("the rules changed since the page was loaded: reload it and try again")
		}
		return r, nil
	}
	return FwdRule{}, errors.New("that port is not open to the Internet (any more): reload the page")
}

// AllowUse ties a rule to a list or makes it reachable from anyone.
func AllowUse(req AllowUseRequest, requester string) (*AllowProbe, bool, error) {
	if r := allowUnsupportedReason(); r != "" {
		return ProbeAllowlists(requester), false, errors.New(r)
	}
	if allowAnonymous(req.Section) && req.Expect == nil {
		return ProbeAllowlists(requester), false, errors.New("missing rule details: reload the page")
	}
	fwWriteMu.Lock()
	defer fwWriteMu.Unlock()
	rule, err := allowFindRule(req.Section, req.Expect)
	if err != nil {
		return ProbeAllowlists(requester), false, err
	}
	secs := allowSections()

	if req.List == "" {
		if rule.AllowedFrom == nil || rule.AllowedFrom.Kind == "anyone" {
			return ProbeAllowlists(requester), false, nil
		}
		if !req.OpenToAnyone {
			return ProbeAllowlists(requester), false, &AllowNeedsForce{Reason: fmt.Sprintf(
				"%s will be reachable from the whole Internet.", allowRuleLabel(rule))}
		}
		rb, err := allowApplyFirewall(allowDetachOps(secs, req.Section), func(after map[string]uciSection) error {
			if s, ok := after[req.Section]; !ok || s.Option("ipset") != "" {
				return errors.New("the limit is still there after the change")
			}
			return nil
		})
		return ProbeAllowlists(requester), rb, err
	}

	allowMu.Lock()
	allowLoadLocked()
	_, lp := allowFindLocked(req.List)
	var l AllowList
	if lp != nil {
		l = *lp
	}
	allowMu.Unlock()
	if lp == nil {
		return ProbeAllowlists(requester), false, fmt.Errorf("list %s not found", req.List)
	}
	if rule.AllowedFrom != nil && rule.AllowedFrom.Kind == "list" && rule.AllowedFrom.List == l.ID &&
		(rule.AllowedFrom.Families == "both" || rule.Kind == "forward") {
		return ProbeAllowlists(requester), false, nil
	}
	allowMu.Lock()
	v4, v6 := allowWriteListFilesLocked(l)
	allowMu.Unlock()
	if !req.Force && !AllowRequesterLocal(requester) && !allowCovers(v4, requester) && !allowCovers(v6, requester) {
		return ProbeAllowlists(requester), false, &AllowNeedsForce{Reason: fmt.Sprintf(
			"You are connected from %s, which %q does not include. If you reach the router through %s, you will lose access.",
			requester, l.Name, allowRuleLabel(rule))}
	}
	setOps, err := allowEnsureSetOps(secs, l.ID)
	if err != nil {
		return ProbeAllowlists(requester), false, err
	}
	attach, sets, err := allowAttachOps(secs, req.Section, l.ID)
	if err != nil {
		return ProbeAllowlists(requester), false, fmt.Errorf("%s: %w", allowRuleLabel(rule), err)
	}
	rb, err := allowApplyFirewall(append(setOps, attach...), func(map[string]uciSection) error {
		return allowVerifyRunning(sets)
	})
	if err == nil {
		allowMu.Lock()
		allowMarkAppliedLocked(l.ID, v4, v6)
		allowMu.Unlock()
		log.Printf("allowlists: %s now limited to the list %q", allowRuleLabel(rule), l.Name)
	}
	return ProbeAllowlists(requester), rb, err
}

func allowRuleLabel(r FwdRule) string {
	if r.Name != "" {
		return fmt.Sprintf("%q", r.Name)
	}
	return "port " + r.SrcDport
}

// allowSyncCompanionsTick repairs IPv6 twins after a rule changed outside
// NetGrip. Skipped while someone else has firewall changes pending.
func allowSyncCompanionsTick() {
	if !allowSupported() {
		return
	}
	allowMu.Lock()
	allowLoadLocked()
	none := len(allowData.Lists) == 0
	allowMu.Unlock()
	if none || !fwWriteMu.TryLock() {
		return
	}
	defer fwWriteMu.Unlock()
	// The refresh just before read the config (cached for two seconds):
	// one `uci show` per tick, not two.
	show, ok := uciShowCached("firewall")
	if !ok {
		return
	}
	ops := allowCompanionSyncOps(parseUCIShow(show, "firewall"))
	if len(ops) == 0 {
		return
	}
	if out, err := uciExec("changes", "firewall"); err != nil || strings.TrimSpace(string(out)) != "" {
		return
	}
	if _, err := allowApplyFirewall(ops, nil); err != nil {
		log.Printf("allowlists: bring the IPv6 twin rules in step: %v", err)
		return
	}
	log.Printf("allowlists: IPv6 twin rules brought in step with their rules (%d changes)", len(ops))
}

// allowCompanionSyncNowLocked brings the twins in step inside another
// firewall change (fwWriteMu held, changes committed, reload to follow).
func allowCompanionSyncNowLocked() error {
	ops := allowCompanionSyncOps(allowSections())
	if len(ops) == 0 {
		return nil
	}
	return allowApplyFn(append(ops, executor.Op{Kind: "uci_commit", Args: []string{"firewall"}}), nil)
}

// ---- take over ----

// AllowTakeoverInfo is what taking a set over proposes: the set, the jobs
// that would be turned off and the entries to start the list with.
func AllowTakeoverInfo(set string) (*AllowExternal, error) {
	ext, err := allowExternalOne(set)
	if err != nil {
		return nil, err
	}
	// Names in the scripts that fill it, kept only when they resolve to an
	// address the set holds now: a script's other words drop out.
	var cands []string
	for _, w := range allowCronWriters(set) {
		if w.Script != "" {
			cands = append(cands, allowHostCandidates(string(allowReadSmall(w.Script)))...)
		} else {
			cands = append(cands, allowHostCandidates(w.Text)...)
		}
	}
	res := allowLookup(cands)
	covered := map[string]bool{}
	sort.Strings(cands)
	seen := map[string]bool{}
	for _, h := range cands {
		if seen[h] {
			continue
		}
		seen[h] = true
		match := false
		for _, a := range res[h].addrs {
			for _, e := range ext.Elements {
				if allowCovers([]string{e}, a.String()) {
					match, covered[e] = true, true
				}
			}
		}
		if match {
			ext.Suggest = append(ext.Suggest, AllowEntry{Value: h})
		}
	}
	for _, e := range ext.Elements {
		if !covered[e] {
			ext.Suggest = append(ext.Suggest, AllowEntry{Value: e, Note: "was in " + set})
		}
	}
	return ext, nil
}

func allowExternalOne(set string) (*AllowExternal, error) {
	for _, e := range allowExternalSets(allowSections(), ProbeFwd().Rules) {
		if e.Set != set {
			continue
		}
		if out, err := allowNftListFn(set); err == nil {
			e.Elements = parseNftElements(out)
		}
		for _, w := range allowCronWriters(set) {
			e.Writers = append(e.Writers, w.Text)
		}
		return &e, nil
	}
	return nil, fmt.Errorf("set %s not found", set)
}

// AllowTakeoverRequest replaces set with a new list.
type AllowTakeoverRequest struct {
	Set       string       `json:"set"`
	Name      string       `json:"name"`
	KeepHours int          `json:"keep_hours"`
	Entries   []AllowEntry `json:"entries"`
	Force     bool         `json:"force"`
}

// AllowTakeover makes a new list of the set's addresses (or names), moves
// every port using the set to the list, removes the set and turns off the
// scheduled jobs that filled it. Only from the router's own networks: it
// changes how the ports are reached and the jobs are not part of a
// firewall rollback.
func AllowTakeover(req AllowTakeoverRequest, requester string) (*AllowProbe, bool, error) {
	if r := allowUnsupportedReason(); r != "" {
		return ProbeAllowlists(requester), false, errors.New(r)
	}
	if !AllowRequesterLocal(requester) {
		return ProbeAllowlists(requester), false, errors.New("taking a set over is only possible from your own network, not through the Internet")
	}
	fwWriteMu.Lock()
	defer fwWriteMu.Unlock()
	ext, err := allowExternalOne(req.Set)
	if err != nil {
		return ProbeAllowlists(requester), false, err
	}
	if !ext.Manage {
		return ProbeAllowlists(requester), false, fmt.Errorf("%s cannot be taken over: %s", req.Set, ext.Why)
	}
	l, err := allowValidate(AllowList{Name: req.Name, KeepHours: req.KeepHours, Entries: req.Entries})
	if err != nil {
		return ProbeAllowlists(requester), false, err
	}
	v4, v6 := allowPreview(l)
	if !req.Force {
		var missing []string
		for _, e := range ext.Elements {
			if !allowCovers(v4, e) && !allowCovers(v6, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			return ProbeAllowlists(requester), false, &AllowNeedsForce{Reason: fmt.Sprintf(
				"These addresses are allowed now and would not be with the new list: %s.", strings.Join(missing, ", "))}
		}
	}

	allowMu.Lock()
	allowLoadLocked()
	if len(allowData.Lists) >= allowMaxLists {
		allowMu.Unlock()
		return ProbeAllowlists(requester), false, fmt.Errorf("at most %d lists", allowMaxLists)
	}
	taken := map[string]bool{}
	for _, x := range allowData.Lists {
		taken[x.ID] = true
	}
	l.ID = allowNewID(l.Name, taken)
	allowData.Lists = append(allowData.Lists, l)
	if err := allowSaveLocked(); err != nil {
		allowData.Lists = allowData.Lists[:len(allowData.Lists)-1]
		allowMu.Unlock()
		return ProbeAllowlists(requester), false, fmt.Errorf("save the lists: %w", err)
	}
	allowMu.Unlock()
	allowRefreshList(l.ID)
	allowMu.Lock()
	v4, v6 = allowWriteListFilesLocked(l)
	allowMu.Unlock()

	undoList := func() {
		allowMu.Lock()
		if i, _ := allowFindLocked(l.ID); i >= 0 {
			allowData.Lists = append(allowData.Lists[:i], allowData.Lists[i+1:]...)
			_ = allowSaveLocked()
		}
		allowMu.Unlock()
	}

	secs := allowSections()
	ops, err := allowEnsureSetOps(secs, l.ID)
	if err != nil {
		undoList()
		return ProbeAllowlists(requester), false, err
	}
	var sets []string
	for _, r := range ext.UsedBy {
		o, s, err := allowAttachOps(secs, r.Section, l.ID)
		if err != nil {
			undoList()
			return ProbeAllowlists(requester), false, fmt.Errorf("%s: %w", allowRuleLabel(r), err)
		}
		ops = append(ops, o...)
		sets = append(sets, s...)
	}
	var old []string
	for name, s := range secs {
		if s.Type == "ipset" && s.Option("name") == req.Set {
			old = append(old, name)
		}
	}
	for _, name := range allowDeleteOrder(old) {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + name}})
	}
	rb, err := allowApplyFirewall(ops, func(after map[string]uciSection) error {
		if refs := allowReferences(after, req.Set); len(refs) > 0 {
			return fmt.Errorf("%s is still used by %s", req.Set, strings.Join(refs, ", "))
		}
		return allowVerifyRunning(sets)
	})
	if err != nil {
		undoList()
		return ProbeAllowlists(requester), rb, err
	}
	allowMu.Lock()
	allowMarkAppliedLocked(l.ID, v4, v6)
	allowMu.Unlock()
	log.Printf("allowlists: the set %s was replaced by the list %q", req.Set, l.Name)

	if w := allowCronWriters(req.Set); len(w) > 0 {
		if err := allowDisableCronLines(w, l.Name); err != nil {
			return ProbeAllowlists(requester), false, fmt.Errorf(
				"the list is in place, but the scheduled job that filled %s could not be turned off: %w (it no longer affects anything)", req.Set, err)
		}
	}
	return ProbeAllowlists(requester), false, nil
}

// allowDeleteOrder orders sections for deletion in one batch: an indexed
// name (@ipset[3]) counts among the sections of its type, so the higher
// index goes first and deleting it does not move the lower one.
func allowDeleteOrder(names []string) []string {
	idx := func(n string) int {
		if i := strings.LastIndex(n, "["); i >= 0 && strings.HasSuffix(n, "]") {
			v := 0
			for _, c := range n[i+1 : len(n)-1] {
				if c < '0' || c > '9' {
					return -1
				}
				v = v*10 + int(c-'0')
			}
			return v
		}
		return -1
	}
	out := append([]string(nil), names...)
	sort.SliceStable(out, func(i, j int) bool { return idx(out[i]) > idx(out[j]) })
	return out
}

// allowAddForwardOps limits a forward being created to a list: the set
// sections and the forward's ipset, plus the set files written so the
// reload fills them.
func allowAddForwardOps(section, id string) ([]executor.Op, []string, error) {
	allowMu.Lock()
	allowLoadLocked()
	_, lp := allowFindLocked(id)
	if lp == nil {
		allowMu.Unlock()
		return nil, nil, fmt.Errorf("list %s not found", id)
	}
	l := *lp
	allowWriteListFilesLocked(l)
	allowMu.Unlock()
	ops, err := allowEnsureSetOps(allowSections(), id)
	if err != nil {
		return nil, nil, err
	}
	set := allowSetName(id, 4)
	return append(ops, setOp("firewall."+section+".ipset", set)), []string{set}, nil
}

// allowForwardAdded records that the reload filled a list's sets.
func allowForwardAdded(id string) {
	allowMu.Lock()
	defer allowMu.Unlock()
	if _, l := allowFindLocked(id); l != nil {
		v4, v6 := allowElements(*l, allowHosts, allowNow())
		allowMarkAppliedLocked(id, v4, v6)
	}
}
