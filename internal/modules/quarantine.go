package modules

// Device quarantine: state, API and the background poller. See
// quarantine_nft.go for how it hooks into the firewall.
//
// A device NetGrip has not been told to trust gets, at most, the internet
// ("internet" mode) or nothing beyond an address and DNS ("nothing" mode),
// in the zones the user chose to protect. Everything about the router's
// layout (zones, their networks, which of them are uplinks, the WAN
// interfaces, the DNS servers DHCP hands out) is read at runtime from its
// own configuration, so the feature works on any firewall4 router.
//
// Scope: the firewall judges traffic that reaches the router - to the
// router itself, and routed between networks or to the internet. Two
// devices on the same bridge or Wi-Fi network talk directly and are not
// separated by this.
//
// Lockout safety:
//   - enabling and changing zones always keep the panel user's device and
//     run inside the confirm window; "Keep" is refused when that device is
//     not in the live approved set;
//   - the generated rules are validated by the kernel (nft -c) before they
//     are written or loaded;
//   - a failed enable or zone change is undone;
//   - revoking the panel user's device, or revoking at all when that device
//     cannot be identified, is refused; resuming a pause keeps it;
//   - a pause "off" lives in the kernel and ends on time without NetGrip;
//   - the poller reconciles the live firewall with the intent, and records
//     the feature as off once the firewall no longer has it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// qStatePath is the persisted intent; a var so tests can redirect it.
var qStatePath = "/etc/netgrip/quarantine.json"

const (
	qMaxPending     = 500
	qPendingTTL     = 7 * 24 * time.Hour
	qNotifiedTTL    = 7 * 24 * time.Hour
	qMaxPause       = 24 * time.Hour
	qMaxLearned     = 64
	qPollInterval   = 5 * time.Second
	qLearnPollEvery = 2 * time.Second
	// qFlushEvery bounds how often the poller's bookkeeping (devices seen,
	// announcements, last-seen times) reaches the flash: a neighbour
	// cycling random MACs must not turn into a write every poll.
	qFlushEvery       = 10 * time.Minute
	qNotifyPerPoll    = 3
	qNotifyPerHour    = 20
	qSummariesPerHour = 2
	qMaxNotified      = 2000
	qMissingToRevert  = 2
	// qFullCheckEvery paces the poller's full router read and drift check.
	qFullCheckEvery = 30 * time.Second
)

var (
	qMu sync.Mutex
	// qMissingPolls counts consecutive polls without the feature in the
	// firewall; one bad read must not turn it off.
	qMissingPolls int
	// qLastFullCheck is when the poller last read the whole router.
	qLastFullCheck time.Time
	// qForceFull asks the next poll for a full check (a failed one).
	qForceFull bool
	qFullFails int
	// The announcement budget (see qNotifyBudget).
	qBudgetStart                  time.Time
	qBudgetUsed, qBudgetSummaries int
)

// QApproved is one trusted device.
type QApproved struct {
	Name string `json:"name,omitempty"`
	At   int64  `json:"at"`
	// Via: "baseline" (trusted when enabling), "manual", "pause" (joined
	// during a learning pause), "panel" (the device the panel was used from).
	Via string `json:"via"`
}

// QPending is a device seen in quarantine.
type QPending struct {
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	IP        string `json:"ip,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// QPause is a time-limited pause. Kind "learn": still enforced, but new
// devices are approved automatically (not the ones already waiting when it
// started, and at most qMaxLearned). Kind "off": nothing is enforced.
type QPause struct {
	Until    int64    `json:"until,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Learned  []string `json:"learned,omitempty"`
	Excluded []string `json:"excluded,omitempty"`
}

func (p QPause) active(now time.Time) bool { return p.Until > now.Unix() }

type qState struct {
	Enabled  bool                 `json:"enabled"`
	Mode     string               `json:"mode"`
	Zones    []string             `json:"zones"`
	Approved map[string]QApproved `json:"approved"`
	Pending  map[string]QPending  `json:"pending"`
	Pause    QPause               `json:"pause"`
	// Notified remembers when each MAC was announced, so forgetting a
	// pending entry or pruning it does not announce it again.
	Notified map[string]int64 `json:"notified,omitempty"`
	// Wifi is the Wi-Fi layer (phase 2).
	Wifi QWifiState `json:"wifi"`
}

// The state is kept in memory as its JSON (a fresh copy per load, so a
// caller that changes it and then fails changes nothing). saveQState
// writes it to the flash at once; saveQStateLazy only updates memory and
// leaves the write to flushQState, at most once per qFlushEvery.
var (
	qCacheMu   sync.Mutex
	qCacheRaw  []byte
	qCachePath string
	qDirty     bool
	qLastFlush time.Time
)

func loadQState() *qState {
	st := &qState{Mode: "internet"}
	qCacheMu.Lock()
	raw := qCacheRaw
	if qCachePath != qStatePath {
		raw = nil
	}
	if raw == nil {
		if b, err := os.ReadFile(qStatePath); err == nil {
			raw = b
			qCacheRaw, qCachePath, qDirty = b, qStatePath, false
		}
	}
	qCacheMu.Unlock()
	if raw != nil {
		_ = json.Unmarshal(raw, st)
	}
	if st.Approved == nil {
		st.Approved = map[string]QApproved{}
	}
	if st.Pending == nil {
		st.Pending = map[string]QPending{}
	}
	if st.Notified == nil {
		st.Notified = map[string]int64{}
	}
	if st.Mode != "nothing" {
		st.Mode = "internet"
	}
	return st
}

func saveQState(st *qState) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	qCacheMu.Lock()
	defer qCacheMu.Unlock()
	if err := writeFileDurable(qStatePath, raw); err != nil {
		return err
	}
	qCacheRaw, qCachePath, qDirty, qLastFlush = raw, qStatePath, false, time.Now()
	return nil
}

// saveQStateLazy records the state in memory only; flushQState writes it.
func saveQStateLazy(st *qState) {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	qCacheMu.Lock()
	qCacheRaw, qCachePath, qDirty = raw, qStatePath, true
	qCacheMu.Unlock()
}

// flushQState writes lazily saved state once qFlushEvery has passed since
// the last write.
func flushQState(now time.Time) {
	qCacheMu.Lock()
	defer qCacheMu.Unlock()
	if !qDirty || qCachePath != qStatePath || now.Sub(qLastFlush) < qFlushEvery {
		return
	}
	if err := writeFileDurable(qStatePath, qCacheRaw); err != nil {
		log.Printf("netgrip: quarantine: saving the device list: %v", err)
		return
	}
	qDirty, qLastFlush = false, now
}

func (st *qState) approvedMACs() []string {
	out := make([]string, 0, len(st.Approved))
	for m := range st.Approved {
		out = append(out, m)
	}
	return sortedMACs(out)
}

// ---- The router's configuration, read at runtime ----

var (
	// Uncached on purpose: right after its own UCI change the feature must
	// see the new sections, and the shared read cache lags by up to 2s.
	uciShowFn = func(pkg string) (string, error) {
		out, err := uciExec("show", pkg)
		return string(out), err
	}
	dumpInterfacesFn = func() ([]ubus.InterfaceState, error) { return ubus.DumpInterfaces() }
)

// QZone is a firewall zone as the quarantine sees it.
type QZone struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	// Wan: an uplink zone (masquerades, or carries a default route).
	// Never protectable.
	Wan bool `json:"wan"`
	// Suggested: a client zone (not an uplink, serves DHCP).
	Suggested bool `json:"suggested"`
	Protected bool `json:"protected"`
}

var reZoneName = regexp.MustCompile(`^[a-zA-Z_.][a-zA-Z0-9_.-]*$`)

// qZoneExtra is what parseFWZonesFrom does not read: per zone name, its
// `device` list and whether it masquerades IPv6.
type qZoneExtra struct {
	devices []string
	masq6   bool
}

func qZoneExtras(uciFirewall string) map[string]qZoneExtra {
	names := map[string]string{}
	ex := map[string]qZoneExtra{}
	for _, line := range strings.Split(uciFirewall, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "firewall.") {
			continue
		}
		sec, opt, hasOpt := strings.Cut(strings.TrimPrefix(key, "firewall."), ".")
		if !hasOpt {
			continue
		}
		e := ex[sec]
		switch opt {
		case "name":
			names[sec] = strings.Trim(val, "'")
		case "device":
			e.devices = append(e.devices, uciListValues(line)...)
		case "masq6":
			e.masq6 = strings.Trim(val, "'") == "1"
		}
		ex[sec] = e
	}
	out := map[string]qZoneExtra{}
	for sec, e := range ex {
		if n := names[sec]; n != "" {
			out[n] = e
		}
	}
	return out
}

// dhcpServedNetworks lists the networks with an enabled DHCP server.
func dhcpServedNetworks(uciDhcp string) map[string]bool {
	type sec struct {
		iface  string
		ignore bool
		isDhcp bool
	}
	secs := map[string]*sec{}
	get := func(name string) *sec {
		if secs[name] == nil {
			secs[name] = &sec{}
		}
		return secs[name]
	}
	for _, line := range strings.Split(uciDhcp, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(key, "dhcp.") {
			continue
		}
		val = strings.Trim(val, "'")
		name, opt, hasOpt := strings.Cut(strings.TrimPrefix(key, "dhcp."), ".")
		switch {
		case !hasOpt:
			get(name).isDhcp = val == "dhcp"
		case opt == "interface":
			get(name).iface = val
		case opt == "ignore":
			get(name).ignore = val == "1"
		}
	}
	out := map[string]bool{}
	for _, s := range secs {
		if s.isDhcp && s.iface != "" && !s.ignore {
			out[s.iface] = true
		}
	}
	return out
}

// qDHCPDNSServers lists the DNS servers DHCP hands out: option 6 in
// dhcp_option / dhcp_option_force, and the `dns` list announced for IPv6.
func qDHCPDNSServers(uciDhcp string) []string {
	out := []string{}
	for _, line := range strings.Split(uciDhcp, "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(key, "dhcp.") {
			continue
		}
		_, opt, _ := strings.Cut(strings.TrimPrefix(key, "dhcp."), ".")
		switch opt {
		case "dhcp_option", "dhcp_option_force":
			for _, v := range uciListValues(line) {
				parts := strings.Split(v, ",")
				if len(parts) > 1 && (parts[0] == "6" || parts[0] == "option:dns-server") {
					out = append(out, parts[1:]...)
				}
			}
		case "dns":
			out = append(out, uciListValues(line)...)
		}
	}
	v4, v6 := splitIPs(out)
	return append(v4, v6...)
}

// qZonesFrom builds the zone list. A zone is an uplink when it masquerades
// (IPv4 or IPv6) or when one of its networks holds a default route. Pure,
// for tests.
// qVPNServerNetworks lists the WireGuard networks that serve peers rather
// than reach the internet: no enabled peer is allowed a wide public range.
// A client tunnel allows 0/0, its two halves, or the "everything but
// private ranges" list (0.0.0.0/5, 8.0.0.0/7, ..., 2000::/3); a server's
// peers get host or site prefixes. Pure, for tests.
func qVPNServerNetworks(uciNetwork string) map[string]bool {
	proto, typ, allowed, disabled := map[string]string{}, map[string]string{}, map[string][]string{}, map[string]bool{}
	for _, line := range strings.Split(uciNetwork, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key = strings.TrimPrefix(key, "network.")
		sec, opt, hasOpt := strings.Cut(key, ".")
		switch {
		case !hasOpt:
			typ[sec] = strings.Trim(val, "'")
		case opt == "proto":
			proto[sec] = strings.Trim(val, "'")
		case opt == "disabled":
			disabled[sec] = strings.Trim(val, "'") == "1"
		case opt == "allowed_ips":
			// A list ('a' 'b') or one string with several values.
			for _, m := range reUCIValue.FindAllStringSubmatch(val, -1) {
				allowed[sec] = append(allowed[sec], strings.FieldsFunc(m[1], func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })...)
			}
		}
	}
	out := map[string]bool{}
	for sec, p := range proto {
		if p == "wireguard" {
			out[sec] = true
		}
	}
	for sec, t := range typ {
		iface, ok := strings.CutPrefix(t, "wireguard_")
		if !ok || disabled[sec] {
			continue
		}
		for _, a := range allowed[sec] {
			if qWidePublicPrefix(a) {
				delete(out, iface)
			}
		}
	}
	return out
}

// qWidePublicPrefix reports a prefix a client tunnel routes the internet
// through: an IPv4 prefix of /8 or wider, or an IPv6 one of /16 or wider,
// that is not entirely private.
func qWidePublicPrefix(s string) bool {
	_, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	ones, bits := n.Mask.Size()
	if bits == 32 {
		return ones <= 8 && !n.IP.IsPrivate() && !n.IP.IsLoopback()
	}
	return ones <= 16 && !n.IP.IsPrivate() && !n.IP.IsLinkLocalUnicast() && !n.IP.IsMulticast()
}

var reUCIValue = regexp.MustCompile(`'([^']*)'`)

func qZonesFrom(uciFirewall, uciDhcp string, protected []string, ifaces []ubus.InterfaceState, vpnServers map[string]bool) []QZone {
	served := dhcpServedNetworks(uciDhcp)
	extras := qZoneExtras(uciFirewall)
	defRoute := map[string]bool{}
	for _, i := range ifaces {
		if i.HasDefaultRoute || i.HasDefaultRoute6 {
			defRoute[i.Name] = true
		}
	}
	prot := map[string]bool{}
	for _, z := range protected {
		prot[z] = true
	}
	out := []QZone{}
	for _, z := range parseFWZonesFrom(uciFirewall) {
		// An uplink zone masquerades or carries a default route. The one
		// masquerading zone that is not an uplink is a VPN server's: its
		// tunnel leads to the peers, not to the internet. A VPN client
		// (pbr, redirect-gateway) often has no default route netifd
		// knows of, so masquerading alone still makes an uplink.
		q := QZone{Name: z.Name, Networks: z.Network, Protected: prot[z.Name]}
		servers := len(z.Network) > 0
		for _, n := range z.Network {
			if !vpnServers[n] {
				servers = false
			}
		}
		q.Wan = (z.Masq || extras[z.Name].masq6) && !servers
		for _, n := range z.Network {
			if defRoute[n] {
				q.Wan = true
			}
		}
		if !q.Wan {
			for _, n := range z.Network {
				if served[n] {
					q.Suggested = true
				}
			}
		}
		out = append(out, q)
	}
	return out
}

// qWanDevicesFrom resolves the uplink interface names: every device of
// every uplink zone, from its networks' runtime state and its own `device`
// list. Patterns (a trailing + or *) cannot go into an nft set and are
// returned separately so the probe can say so. Pure, for tests.
func qWanDevicesFrom(zones []QZone, extras map[string]qZoneExtra, ifaces []ubus.InterfaceState) (devs, patterns []string) {
	byName := map[string]ubus.InterfaceState{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	for _, z := range zones {
		if !z.Wan {
			continue
		}
		for _, n := range z.Networks {
			if i, ok := byName[n]; ok {
				for _, d := range []string{i.L3Device, i.Device} {
					if d != "" && !strings.HasPrefix(d, "/") {
						devs = append(devs, d)
					}
				}
			}
		}
		for _, d := range extras[z.Name].devices {
			if strings.HasSuffix(d, "+") || strings.HasSuffix(d, "*") {
				patterns = append(patterns, d)
			} else {
				devs = append(devs, d)
			}
		}
	}
	sort.Strings(patterns)
	return sortedIfnames(devs), patterns
}

// qRouter is one read of everything the feature needs from the router.
type qRouter struct {
	firewall    string
	zones       []QZone
	wan         []string
	wanPatterns []string
	dns         []string
	sections    []string // the feature's own include sections
	actual      []string // zones the include sections actually protect
}

// readQRouter reads the router's configuration. A failed `uci show` is an
// error: deciding anything from an empty read could delete or skip
// sections that exist.
func readQRouter() (qRouter, error) {
	fw, err := uciShowFn("firewall")
	if err != nil {
		return qRouter{}, fmt.Errorf("reading the firewall config: %w", err)
	}
	dhcp, err := uciShowFn("dhcp")
	if err != nil {
		return qRouter{}, fmt.Errorf("reading the DHCP config: %w", err)
	}
	netw, err := uciShowFn("network")
	if err != nil {
		return qRouter{}, fmt.Errorf("reading the network config: %w", err)
	}
	ifaces, err := dumpInterfacesFn()
	if err != nil {
		return qRouter{}, fmt.Errorf("reading the interfaces: %w", err)
	}
	r := qRouter{firewall: fw, sections: qIncludeSections(fw), actual: qActualZones(fw)}
	r.zones = qZonesFrom(fw, dhcp, r.actual, ifaces, qVPNServerNetworks(netw))
	r.wan, r.wanPatterns = qWanDevicesFrom(r.zones, qZoneExtras(fw), ifaces)
	r.wan = qStickyWan(r.zones, ifaces, r.wan, time.Now())
	r.dns = qDHCPDNSServers(dhcp)
	return r, nil
}

// Uplink devices exist only while their link is up (a PPPoE session's
// interface goes away on every reconnect, and a zone that is an uplink by
// its default route alone stops being one meanwhile). qStickyWan keeps an
// uplink device in the set for qWanGrace after it was last seen, so a
// sync during a reconnect or a failover does not cut quarantined devices
// off the internet. A device an internal network uses now leaves at once.
const qWanGrace = 10 * time.Minute

var (
	qWanStickyMu sync.Mutex
	qWanSticky   = map[string]time.Time{} // device -> last seen as an uplink device
	qWanNets     = map[string]time.Time{} // network -> last seen as an uplink
)

func qStickyWan(zones []QZone, ifaces []ubus.InterfaceState, devs []string, now time.Time) []string {
	qWanStickyMu.Lock()
	defer qWanStickyMu.Unlock()
	uplink := map[string]bool{}
	for _, z := range zones {
		if z.Wan {
			for _, n := range z.Networks {
				uplink[n] = true
			}
		}
	}
	for n := range uplink {
		qWanNets[n] = now
	}
	for n, seen := range qWanNets {
		if now.Sub(seen) > qWanGrace {
			delete(qWanNets, n)
		}
	}
	internal := map[string]bool{}
	for _, i := range ifaces {
		if _, recent := qWanNets[i.Name]; recent {
			continue
		}
		for _, d := range []string{i.L3Device, i.Device} {
			if d != "" {
				internal[d] = true
			}
		}
	}
	for _, d := range devs {
		qWanSticky[d] = now
	}
	out := append([]string(nil), devs...)
	for d, seen := range qWanSticky {
		if internal[d] || now.Sub(seen) > qWanGrace {
			delete(qWanSticky, d)
			continue
		}
		out = append(out, d)
	}
	return sortedIfnames(out)
}

func (r qRouter) ruleSet(st *qState) qRuleSet {
	return qRuleSet{Mode: st.Mode, Approved: st.approvedMACs(), Wan: r.wan, DNS: r.dns}
}

// ---- UCI include sections ----

// qIncludeSections lists the firewall sections the feature owns.
func qIncludeSections(uciFirewall string) []string {
	out := []string{}
	for _, line := range strings.Split(uciFirewall, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.Trim(val, "'") != "include" {
			continue
		}
		sec := strings.TrimPrefix(key, "firewall.")
		if sec != key && !strings.Contains(sec, ".") && (strings.HasPrefix(sec, qSectionPrefix) || strings.HasPrefix(sec, qLegacyPrefix)) {
			out = append(out, sec)
		}
	}
	sort.Strings(out)
	return out
}

// qActualZones reads which zones the include sections hook into: the
// actual protection, whatever the saved intent says (a confirm revert, or
// any other firewall restore, changes the sections and not the intent).
func qActualZones(uciFirewall string) []string {
	out := []string{}
	for _, line := range strings.Split(uciFirewall, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		owned := strings.HasPrefix(key, "firewall."+qSectionPrefix+"input_") || strings.HasPrefix(key, "firewall."+qLegacyPrefix+"in_")
		if !ok || !owned || !strings.HasSuffix(key, ".chain") {
			continue
		}
		if z, ok := strings.CutPrefix(strings.Trim(val, "'"), "input_"); ok && z != "" {
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

// qIncludeOps rebuilds the include sections for zones: delete every owned
// section, then add the table include and two chain includes per zone.
// Ends with commit and a firewall reload.
func qIncludeOps(existing []string, zones []string) []executor.Op {
	ops := []executor.Op{}
	for _, s := range existing {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"firewall." + s}})
	}
	add := func(sec, path, position, chain string) {
		base := "firewall." + sec
		ops = append(ops,
			executor.Op{Kind: "uci_set", Args: []string{base, "include"}},
			executor.Op{Kind: "uci_set", Args: []string{base + ".type", "nftables"}},
			executor.Op{Kind: "uci_set", Args: []string{base + ".path", path}},
			executor.Op{Kind: "uci_set", Args: []string{base + ".position", position}},
		)
		if chain != "" {
			ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{base + ".chain", chain}})
		}
	}
	if len(zones) > 0 {
		add(qSectionTable, qTableFile(), "table-prepend", "")
		for i, z := range zones {
			add(fmt.Sprintf("%sinput_%d", qSectionPrefix, i), qInputFile(), "chain-prepend", "input_"+z)
			add(fmt.Sprintf("%sforward_%d", qSectionPrefix, i), qForwardFile(), "chain-prepend", "forward_"+z)
		}
	}
	return append(ops,
		executor.Op{Kind: "uci_commit", Args: []string{"firewall"}},
		executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}},
	)
}

// applyQIncludes is a seam: it runs the UCI ops (tests record them). It
// refuses when the firewall config has uncommitted changes made elsewhere:
// its commit would publish them too.
var applyQIncludes = func(ops []executor.Op) error {
	if err := QuarantinePendingCheck([]string{"firewall"}); err != nil {
		return err
	}
	return qApplyClean(ops)
}

// qVerifyLive checks the actual result: chains loaded, every protected
// zone jumps into them, and the must-keep MAC is in the live set.
var qVerifyLive = func(zones []string, mustKeep string) error {
	if !qLiveChainsPresent() {
		return errors.New("the firewall did not load the quarantine chains")
	}
	for _, z := range zones {
		for _, c := range []struct{ chain, jump string }{{"input_" + z, qChainInput}, {"forward_" + z, qChainForward}} {
			out, err := nftRunFn("", "list", "chain", "inet", qTable, c.chain)
			if err != nil || !strings.Contains(string(out), "jump "+c.jump) {
				return fmt.Errorf("zone %s: chain %s does not jump to %s", z, c.chain, c.jump)
			}
		}
	}
	if mustKeep != "" && !qLiveApproved(mustKeep) {
		return fmt.Errorf("your device %s is not in the live approved set", mustKeep)
	}
	return nil
}

func qLiveApproved(mac string) bool {
	elems, err := qSetElements(qSetOK)
	if err != nil {
		return false
	}
	for _, e := range elems {
		if strings.EqualFold(e, mac) {
			return true
		}
	}
	return false
}

// ---- Probe ----

// QDevice is a device row for the UI (pending or approved).
type QDevice struct {
	MAC       string `json:"mac"`
	Name      string `json:"name,omitempty"`
	IP        string `json:"ip,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Random    bool   `json:"random,omitempty"`
	FirstSeen int64  `json:"first_seen,omitempty"`
	LastSeen  int64  `json:"last_seen,omitempty"`
	At        int64  `json:"at,omitempty"`
	Via       string `json:"via,omitempty"`
}

// QuarantineProbe is the API view. Enabled is the intent; Active and the
// zones' Protected flags are what the firewall actually runs.
type QuarantineProbe struct {
	Applicable bool       `json:"applicable"`
	Reason     string     `json:"reason,omitempty"`
	Enabled    bool       `json:"enabled"`
	Active     bool       `json:"active"`
	Mode       string     `json:"mode"`
	Zones      []QZone    `json:"zones"`
	Wan        []string   `json:"wan"`
	Approved   []QDevice  `json:"approved"`
	Pending    []QDevice  `json:"pending"`
	Pause      QPause     `json:"pause"`
	Issues     []string   `json:"issues"`
	Wifi       QWifiProbe `json:"wifi"`
}

// qApplicable: a gateway with firewall4 and nft.
var qApplicable = func() (bool, string) {
	if probeModeFn().Mode == "ap" {
		return false, "needs the router to be the gateway (it is an access point)"
	}
	if !executor.ServiceEnabled("firewall") {
		return false, "needs the firewall service"
	}
	if _, err := os.Stat("/sbin/fw4"); err != nil {
		return false, "needs firewall4 (nftables); this firmware uses the older iptables firewall"
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return false, "needs the nft tool"
	}
	return true, ""
}

func ProbeQuarantine() QuarantineProbe {
	qMu.Lock()
	defer qMu.Unlock()
	return probeQuarantineLocked()
}

// probeQuarantineLocked always describes the feature when it is enabled,
// even if the router no longer looks applicable: the rules may still be
// enforced, and the user must be able to manage or turn them off.
func probeQuarantineLocked() QuarantineProbe {
	st := loadQState()
	ok, why := qApplicable()
	p := QuarantineProbe{
		Applicable: ok, Reason: why, Enabled: st.Enabled, Mode: st.Mode,
		Zones: []QZone{}, Wan: []string{}, Approved: []QDevice{}, Pending: []QDevice{},
		Pause: st.Pause, Issues: []string{},
		Wifi: QWifiProbe{SSIDs: []QWifiSSID{}, Issues: []string{}},
	}
	if !ok && !st.Enabled {
		return p
	}
	r, err := readQRouter()
	if err != nil {
		p.Issues = append(p.Issues, err.Error())
	}
	p.Zones = []QZone{}
	for _, z := range r.zones {
		if z.Name != qNet { // the Wi-Fi layer's own zone is not the user's to pick
			p.Zones = append(p.Zones, z)
		}
	}
	p.Wan = append([]string{}, r.wan...)
	if err == nil {
		p.Wifi = qWifiProbeLocked(st, r)
	}
	p.Active = len(r.sections) > 0 && qLiveChainsPresent()
	if !p.Pause.active(time.Now()) {
		p.Pause = QPause{}
	}
	p.Pause.Excluded = nil
	ident := qIdentities()
	for mac, a := range st.Approved {
		d := ident.device(mac)
		d.At, d.Via = a.At, a.Via
		if a.Name != "" {
			d.Name = a.Name
		}
		p.Approved = append(p.Approved, d)
	}
	for mac, pe := range st.Pending {
		d := ident.device(mac)
		d.FirstSeen, d.LastSeen = pe.FirstSeen, pe.LastSeen
		if d.IP == "" {
			d.IP = pe.IP
		}
		if d.Hostname == "" {
			d.Hostname = pe.Hostname
		}
		p.Pending = append(p.Pending, d)
	}
	sort.Slice(p.Approved, func(i, j int) bool { return p.Approved[i].MAC < p.Approved[j].MAC })
	sort.Slice(p.Pending, func(i, j int) bool { return p.Pending[i].LastSeen > p.Pending[j].LastSeen })
	if st.Enabled {
		if !p.Active {
			p.Issues = append(p.Issues, "enabled, but the firewall is not running the quarantine rules")
		}
		known := map[string]bool{}
		for _, z := range r.zones {
			known[z.Name] = true
		}
		for _, z := range r.actual {
			if !known[z] {
				p.Issues = append(p.Issues, fmt.Sprintf("protected zone %q no longer exists: its devices are not checked", z))
			}
		}
		if st.Mode == "internet" && len(r.wan) == 0 {
			p.Issues = append(p.Issues, "no uplink interface found: quarantined devices get no internet")
		}
		for _, pat := range r.wanPatterns {
			p.Issues = append(p.Issues, fmt.Sprintf("uplink device pattern %q cannot be matched: quarantined devices get no internet through it", pat))
		}
	}
	return p
}

// qIdent holds the lookups used to describe a MAC.
type qIdent struct {
	arp    map[string]string // mac -> ip
	leases map[string]ubus.Lease
	meta   map[string]ClientMeta
}

var qIdentities = func() qIdent {
	id := qIdent{arp: localArp(), leases: map[string]ubus.Lease{}, meta: clientMeta()}
	if leases, _, err := leasesForClients(); err == nil {
		for _, l := range leases {
			id.leases[strings.ToLower(l.MAC)] = l
		}
	}
	return id
}

func (id qIdent) device(mac string) QDevice {
	d := QDevice{MAC: mac, IP: id.arp[mac]}
	if l, ok := id.leases[mac]; ok {
		d.Hostname = l.Hostname
		if d.IP == "" {
			d.IP = l.IP
		}
	}
	if d.Hostname == "*" {
		d.Hostname = ""
	}
	if m, ok := id.meta[mac]; ok && m.Name != "" {
		d.Name = m.Name
	}
	d.Vendor, d.Random = vendorFor(mac)
	return d
}

// ---- The panel user's device ----

// qNormalizeIP strips an IPv6 zone ("fe80::1%br-lan") and brackets.
func qNormalizeIP(ip string) string {
	ip = strings.Trim(ip, "[]")
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		ip = ip[:i]
	}
	return ip
}

// requesterMACFn resolves the panel user's device MAC from its IP.
var requesterMACFn = func(ip string) string {
	ip = qNormalizeIP(ip)
	if ip == "" {
		return ""
	}
	found := ""
	for mac, a := range localArp() {
		if a != ip {
			continue
		}
		if found != "" && found != mac {
			return "" // the address answers from two devices: no answer
		}
		found = mac
	}
	if found != "" {
		return found
	}
	out, err := exec.Command("ip", "neigh", "show", "to", ip).Output()
	if err != nil {
		return ""
	}
	return parseNeighMAC(string(out))
}

// parseNeighMAC reads the lladdr of a resolved `ip neigh` line. Two
// different answers (the same address on two interfaces) are no answer.
func parseNeighMAC(out string) string {
	found := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" && reMac.MatchString(f[i+1]) {
				m := strings.ToLower(f[i+1])
				if found != "" && found != m {
					return ""
				}
				found = m
			}
		}
	}
	return found
}

// QuarantineRequesterMAC is the panel user's MAC, or "".
func QuarantineRequesterMAC(ip string) string { return requesterMACFn(ip) }

// QuarantineKeepCheck runs before a confirm window is kept. The Keep
// request may ride a connection opened before the change, which the
// firewall lets through whatever the change did to new ones. It refuses
// only when there is proof the panel user is being quarantined: the device
// is not approved and the quarantine has recorded it, i.e. its new
// connections from a protected zone are being refused right now. A device
// on an unprotected network is never in that record, and nothing is
// refused while protection is paused.
func QuarantineKeepCheck(requesterIP string) error {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled || st.offRemaining(time.Now()) > 0 || !qLiveChainsPresent() {
		return nil
	}
	mac := requesterMACFn(requesterIP)
	if mac == "" || qLiveApproved(mac) {
		return nil
	}
	seen, err := qSeenFn()
	if err != nil {
		return nil
	}
	for _, e := range seen {
		if strings.EqualFold(e.Val, mac) {
			return fmt.Errorf("your device %s is being quarantined: keeping this change would cut it off, so it will be undone", mac)
		}
	}
	return nil
}

// ---- Baseline candidates ----

// QCandidate is a device the enable wizard offers to trust.
type QCandidate struct {
	QDevice
	Sources   []string `json:"sources"`
	Requester bool     `json:"requester,omitempty"`
}

var listClientsFn = func(ip string) []Client { return ListClients(ip) }

// QuarantineCandidates lists every device the router knows of right now or
// recently: associated and bridge-learned clients, leases, the neighbour
// table, DHCP reservations and named clients.
func QuarantineCandidates(requesterIP string) []QCandidate {
	ident := qIdentities()
	req := requesterMACFn(requesterIP)
	byMAC := map[string]*QCandidate{}
	add := func(mac, source string) {
		mac = strings.ToLower(mac)
		if !reMac.MatchString(mac) || mac == "00:00:00:00:00:00" || qMulticast(mac) {
			return
		}
		c := byMAC[mac]
		if c == nil {
			c = &QCandidate{QDevice: ident.device(mac)}
			byMAC[mac] = c
		}
		for _, s := range c.Sources {
			if s == source {
				return
			}
		}
		c.Sources = append(c.Sources, source)
	}
	for _, c := range listClientsFn(requesterIP) {
		src := "cable"
		if strings.HasPrefix(c.Type, "wifi") {
			src = "wifi"
		}
		add(c.MAC, src)
		if cc := byMAC[strings.ToLower(c.MAC)]; cc != nil && cc.Name == "" {
			cc.Name = c.Name
		}
	}
	for mac := range ident.leases {
		add(mac, "lease")
	}
	for mac := range ident.arp {
		add(mac, "neighbour")
	}
	for mac := range dhcpReservations() {
		add(mac, "reserved")
	}
	for mac, m := range ident.meta {
		if m.Name != "" {
			add(mac, "named")
		}
	}
	if req != "" {
		add(req, "you")
		byMAC[req].Requester = true
	}
	out := make([]QCandidate, 0, len(byMAC))
	for _, c := range byMAC {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requester != out[j].Requester {
			return out[i].Requester
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func qMulticast(mac string) bool {
	var first byte
	for _, c := range []byte(mac[:2]) {
		first = first<<4 | hexVal(c)
	}
	return first&0x01 != 0
}

// ---- Actions ----

// QEnableRequest turns the quarantine on.
type QEnableRequest struct {
	Mode  string   `json:"mode"`
	Zones []string `json:"zones"`
	// Approve: the baseline, the devices trusted from the start.
	Approve []QApproveItem `json:"approve"`
	// AllowNoRequester: go ahead although the panel user's MAC is unknown
	// (panel reached over a VPN or from another network).
	AllowNoRequester bool `json:"allow_no_requester,omitempty"`
}

type QApproveItem struct {
	MAC  string `json:"mac"`
	Name string `json:"name,omitempty"`
}

func validMode(m string) bool { return m == "internet" || m == "nothing" }

// validateZones checks that every zone exists and is not an uplink.
func validateZones(req []string, zones []QZone) ([]string, error) {
	if len(req) == 0 {
		return nil, errors.New("choose at least one zone to protect")
	}
	known := map[string]QZone{}
	for _, z := range zones {
		known[z.Name] = z
	}
	seen := map[string]bool{}
	out := []string{}
	for _, name := range req {
		z, ok := known[name]
		switch {
		case !reZoneName.MatchString(name) || !ok || name == qNet:
			return nil, fmt.Errorf("unknown zone %q", name)
		case z.Wan:
			return nil, fmt.Errorf("zone %q is an uplink (it masquerades or carries a default route) and cannot be protected", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

var errNoRequester = errors.New("cannot tell which device you are using (no MAC for your address); open the panel from a device on the local network, or confirm you accept the risk")

// qKeepRequester approves the panel user's device. It returns the MAC, ""
// when unknown, or an error when unknown and not explicitly accepted.
func qKeepRequester(st *qState, requesterIP string, allowUnknown bool) (string, error) {
	mac := requesterMACFn(requesterIP)
	if mac == "" {
		if !allowUnknown {
			return "", errNoRequester
		}
		return "", nil
	}
	if _, ok := st.Approved[mac]; !ok {
		st.Approved[mac] = QApproved{At: time.Now().Unix(), Via: "panel"}
	}
	delete(st.Pending, mac)
	return mac, nil
}

// QuarantineEnable turns the feature on. The caller (the server) holds the
// confirm window around it.
func QuarantineEnable(req QEnableRequest, requesterIP string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	if ok, why := qApplicable(); !ok {
		return probeQuarantineLocked(), errors.New(why)
	}
	if !validMode(req.Mode) {
		return probeQuarantineLocked(), errors.New("mode must be internet or nothing")
	}
	r, err := readQRouter()
	if err != nil {
		return probeQuarantineLocked(), err
	}
	zones, err := validateZones(req.Zones, r.zones)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	st := loadQState()
	// Anything left of a Wi-Fi layer from before (a failed teardown) goes
	// first: phase 1 starts without it.
	if !st.Enabled {
		if err := qWifiTeardownLocked(st); err != nil {
			return probeQuarantineLocked(), fmt.Errorf("removing what is left of the Wi-Fi layer: %w", err)
		}
	}
	now := time.Now().Unix()
	for _, a := range req.Approve {
		mac := strings.ToLower(strings.TrimSpace(a.MAC))
		if !reMac.MatchString(mac) {
			return probeQuarantineLocked(), fmt.Errorf("invalid MAC %q", a.MAC)
		}
		if _, ok := st.Approved[mac]; !ok {
			st.Approved[mac] = QApproved{Name: qDeviceName(mac, a.Name), At: now, Via: "baseline"}
		}
		delete(st.Pending, mac)
	}
	requester, err := qKeepRequester(st, requesterIP, req.AllowNoRequester)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	st.Mode = req.Mode
	st.Zones = zones
	st.Pause = QPause{}
	rs := r.ruleSet(st)
	if err := writeQFiles(rs); err != nil {
		return probeQuarantineLocked(), fmt.Errorf("the quarantine rules were refused, nothing was changed: %w", err)
	}
	st.Enabled = true
	if err := saveQState(st); err != nil {
		removeQFiles()
		return probeQuarantineLocked(), err
	}
	if err := applyQIncludes(qIncludeOps(r.sections, zones)); err != nil {
		_ = qDisableLocked(st)
		return probeQuarantineLocked(), fmt.Errorf("applying the firewall change failed and was undone: %w", err)
	}
	if err := qVerifyLive(zones, requester); err != nil {
		_ = qDisableLocked(st)
		return probeQuarantineLocked(), fmt.Errorf("the quarantine did not come up as expected and was turned off again: %w", err)
	}
	qMissingPolls = 0
	log.Printf("netgrip: quarantine enabled (mode %s, zones %s, %d approved)", st.Mode, strings.Join(zones, ","), len(st.Approved))
	return probeQuarantineLocked(), nil
}

// qDisableLocked removes the include sections, then the files; the
// approvals are kept so turning the feature back on remembers them.
//
// The intent becomes "off" only once the sections are gone: if removing
// them fails, the rules are still enforced, and the feature must stay
// visible and manageable (the poller keeps reconciling it).
func qDisableLocked(st *qState) error {
	// The Wi-Fi layer first: its SSIDs get their own networks back.
	if err := qWifiTeardownLocked(st); err != nil {
		return fmt.Errorf("the Wi-Fi layer could not be removed, the quarantine stays on: %w", err)
	}
	fw, err := uciShowFn("firewall")
	if err != nil {
		return fmt.Errorf("reading the firewall config: %w", err)
	}
	if secs := qIncludeSections(fw); len(secs) > 0 {
		if err := applyQIncludes(qIncludeOps(secs, nil)); err != nil {
			// Keep the files: the sections still point at them, and a jump
			// without its chains would break the firewall at the next load.
			return fmt.Errorf("the firewall still runs the quarantine: %w", err)
		}
	}
	st.Enabled = false
	st.Pause = QPause{}
	_ = saveQState(st)
	removeQFiles()
	return nil
}

// QuarantineDisable turns the feature off. Removing rules cannot lock
// anyone out, so no confirm window is needed.
func QuarantineDisable() (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	err := qDisableLocked(loadQState())
	if err == nil {
		log.Printf("netgrip: quarantine disabled")
	}
	return probeQuarantineLocked(), err
}

// QuarantineSetZones changes the protected zones (a firewall reload; the
// server wraps it in the confirm window). It keeps the panel user's device
// like enabling does, and puts the previous zones back if it fails.
func QuarantineSetZones(zones []string, requesterIP string, allowUnknown bool) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return probeQuarantineLocked(), errors.New("the quarantine is off")
	}
	r, err := readQRouter()
	if err != nil {
		return probeQuarantineLocked(), err
	}
	z, err := validateZones(zones, r.zones)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	requester, err := qKeepRequester(st, requesterIP, allowUnknown)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	if err := writeQFiles(r.ruleSet(st)); err != nil {
		return probeQuarantineLocked(), err
	}
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	prevZones := st.Zones
	st.Zones = z
	hook := qHookZones(st)
	if err := applyQIncludes(qIncludeOps(r.sections, hook)); err != nil {
		qRestoreZonesLocked(r.actual)
		return probeQuarantineLocked(), fmt.Errorf("changing the zones failed; the previous zones were put back: %w", err)
	}
	if err := qVerifyLive(hook, requester); err != nil {
		qRestoreZonesLocked(r.actual)
		return probeQuarantineLocked(), fmt.Errorf("the new zones did not come up as expected; the previous zones were put back: %w", err)
	}
	// The Wi-Fi layer follows: SSIDs of newly protected zones join it,
	// those of unprotected ones get their own networks back.
	if st.Wifi.Enabled {
		if err := qWifiFollowZonesLocked(st); err != nil {
			st.Zones = prevZones
			qRestoreZonesLocked(r.actual)
			return probeQuarantineLocked(), fmt.Errorf("the Wi-Fi layer could not follow the new zones; the previous zones were put back: %w", err)
		}
	}
	_ = saveQState(st)
	return probeQuarantineLocked(), nil
}

// qRestoreZonesLocked puts the include sections back to prev (best effort).
func qRestoreZonesLocked(prev []string) {
	fw, err := uciShowFn("firewall")
	if err != nil {
		log.Printf("netgrip: quarantine: cannot restore the previous zones: %v", err)
		return
	}
	if err := applyQIncludes(qIncludeOps(qIncludeSections(fw), prev)); err != nil {
		log.Printf("netgrip: quarantine: restoring the previous zones failed: %v", err)
	}
}

// qSyncLocked writes the include file and brings the live firewall in line
// with the state: chains, sets and the kernel-timed pause "off". The
// poller calls it again whenever the live state drifts, so a failure here
// is retried.
func qSyncLocked(st *qState, r qRouter) error {
	rs := r.ruleSet(st)
	if err := writeQFiles(rs); err != nil {
		return err
	}
	if !qLiveChainsPresent() {
		return nil
	}
	if err := nftApply(renderQRuntimeUpdate(rs)); err != nil {
		return err
	}
	return nftApply(qOffPauseScript(st.offRemaining(time.Now())))
}

func (st *qState) offRemaining(now time.Time) int64 {
	if st.Enabled && st.Pause.Kind == "off" && st.Pause.active(now) {
		return st.Pause.Until - now.Unix()
	}
	return 0
}

// qChangeLocked saves the new intent, then applies it. The intent is saved
// first on purpose: if applying fails, the poller keeps retrying.
func qChangeLocked(st *qState) error {
	if err := saveQState(st); err != nil {
		return err
	}
	if !st.Enabled {
		return nil
	}
	r, err := readQRouter()
	if err != nil {
		return err
	}
	if err := qSyncLocked(st, r); err != nil {
		return fmt.Errorf("saved, but not applied yet (it will be retried): %w", err)
	}
	if st.Wifi.Enabled {
		if _, err := qWifiSyncLocked(st, r, time.Now()); err != nil {
			return fmt.Errorf("saved, but the Wi-Fi entries are not updated yet (it will be retried): %w", err)
		}
	}
	return nil
}

// QuarantineSetMode switches between "internet" and "nothing". It only
// changes what unapproved devices get, so no confirm window is needed.
func QuarantineSetMode(mode string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	if !validMode(mode) {
		return probeQuarantineLocked(), errors.New("mode must be internet or nothing")
	}
	st := loadQState()
	st.Mode = mode
	err := qChangeLocked(st)
	return probeQuarantineLocked(), err
}

// qDeviceName is the name to keep for a device: the client list falls
// back to the MAC when it knows no name, and that is not a name.
func qDeviceName(mac, name string) string {
	n := qCleanName(name)
	if strings.EqualFold(n, mac) {
		return ""
	}
	return n
}

func qCleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len([]rune(s)) > 64 {
		s = string([]rune(s)[:64])
	}
	return s
}

// QuarantineApprove trusts devices. Granting access cannot lock anyone out.
func QuarantineApprove(items []QApproveItem) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	if len(items) == 0 {
		return probeQuarantineLocked(), errors.New("nothing to approve")
	}
	st := loadQState()
	now := time.Now().Unix()
	for _, it := range items {
		mac := strings.ToLower(strings.TrimSpace(it.MAC))
		if !reMac.MatchString(mac) {
			return probeQuarantineLocked(), fmt.Errorf("invalid MAC %q", it.MAC)
		}
		a := st.Approved[mac]
		if a.At == 0 {
			a = QApproved{At: now, Via: "manual"}
		}
		if n := qDeviceName(mac, it.Name); n != "" {
			a.Name = n
		}
		st.Approved[mac] = a
		delete(st.Pending, mac)
	}
	err := qChangeLocked(st)
	return probeQuarantineLocked(), err
}

// QuarantineRevoke withdraws trust. Refused for the panel user's own
// device, and refused when that device cannot be identified (the MAC being
// revoked might be the one carrying the user's traffic) unless force.
// Connections already open stay up until they end.
func QuarantineRevoke(mac, requesterIP string, force bool) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !reMac.MatchString(mac) {
		return probeQuarantineLocked(), errors.New("invalid MAC")
	}
	switch req := requesterMACFn(requesterIP); {
	case req == mac:
		return probeQuarantineLocked(), errors.New("this is the device you are using: revoking it would cut off your access to the panel")
	case req == "" && !force:
		return probeQuarantineLocked(), errors.New("cannot tell which device you are using, so revoking might cut off your own access; revoke from a device on the local network")
	}
	st := loadQState()
	if _, ok := st.Approved[mac]; !ok {
		return probeQuarantineLocked(), errors.New("not an approved device")
	}
	delete(st.Approved, mac)
	err := qChangeLocked(st)
	return probeQuarantineLocked(), err
}

// QuarantineForget drops a pending entry and its live "seen" record. The
// device is not announced again for a week (it stays quarantined, and
// reappears in the list when it is active again).
func QuarantineForget(mac string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	st := loadQState()
	delete(st.Pending, mac)
	if reMac.MatchString(mac) {
		_, _ = nftRunFn("", "delete", "element", "inet", qTable, qSetSeen, "{", mac, "}")
	}
	return probeQuarantineLocked(), saveQState(st)
}

// QuarantinePause pauses for minutes (capped). kind "learn" or "off".
func QuarantinePause(minutes int, kind string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	if kind != "learn" && kind != "off" {
		return probeQuarantineLocked(), errors.New("pause kind must be learn or off")
	}
	d := time.Duration(minutes) * time.Minute
	if d <= 0 {
		return probeQuarantineLocked(), errors.New("pause length must be positive")
	}
	if d > qMaxPause {
		d = qMaxPause
	}
	st := loadQState()
	if !st.Enabled {
		return probeQuarantineLocked(), errors.New("the quarantine is off")
	}
	learned := st.Pause.Learned
	if st.Pause.Kind != kind || !st.Pause.active(time.Now()) {
		learned = nil
	}
	p := QPause{Until: time.Now().Add(d).Unix(), Kind: kind, Learned: learned}
	if kind == "learn" {
		// Devices already waiting are not approved by a learning pause:
		// only devices that join during it. "Waiting" covers the list, the
		// devices announced earlier (forgotten or pruned since) and the
		// ones the firewall recorded but the poller has not seen yet.
		ex := map[string]bool{}
		for mac := range st.Pending {
			ex[mac] = true
		}
		for mac := range st.Notified {
			ex[mac] = true
		}
		if seen, err := qSeenFn(); err == nil {
			for _, e := range seen {
				ex[strings.ToLower(e.Val)] = true
			}
		}
		for mac := range ex {
			p.Excluded = append(p.Excluded, mac)
		}
		sort.Strings(p.Excluded)
	}
	st.Pause = p
	err := qChangeLocked(st)
	return probeQuarantineLocked(), err
}

// QuarantineResume ends a pause now. The panel user's device is approved
// first: during a pause it may have joined without being approved.
func QuarantineResume(requesterIP string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if st.Enabled {
		_, _ = qKeepRequester(st, requesterIP, true)
	}
	qEndPauseLocked(st)
	err := qChangeLocked(st)
	return probeQuarantineLocked(), err
}

func qEndPauseLocked(st *qState) {
	if st.Pause.Kind == "learn" && len(st.Pause.Learned) > 0 {
		learned := append([]string(nil), st.Pause.Learned...)
		go qNotifyLearned(learned, qChannelsFn, qNotifyFn)
	}
	st.Pause = QPause{}
}

// ---- Poller ----

var qPollerOnce sync.Once

// StartQuarantine runs the background poller: it records quarantined
// devices, approves new ones during a learning pause, ends pauses, keeps
// the live firewall in line with the intent and notices when the firewall
// no longer has the feature (a confirm revert, or the sections removed).
func StartQuarantine() {
	qPollerOnce.Do(func() {
		go func() {
			for {
				time.Sleep(qPollTick())
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("netgrip: quarantine poller: %v", r)
						}
					}()
					qPoll(time.Now())
				}()
			}
		}()
	})
}

func qPollTick() time.Duration {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if st.Pause.active(time.Now()) && st.Pause.Kind == "learn" {
		return qLearnPollEvery
	}
	return qPollInterval
}

var qSeenFn = func() ([]qElem, error) { return qSetElementsTimed(qSetSeen) }

// qLiveDrifted reports whether the live firewall or the include file
// differs from what the intent renders.
var qLiveDrifted = func(st *qState, r qRouter, now time.Time) bool {
	rs := r.ruleSet(st)
	if file, err := os.ReadFile(qTableFile()); err != nil || string(file) != renderQTable(rs) {
		return true
	}
	if live, err := qSetElements(qSetOK); err != nil || strings.Join(sortedMACs(live), ",") != strings.Join(rs.Approved, ",") {
		return true
	}
	if live, err := qSetElements(qSetWan); err != nil || strings.Join(sortedIfnames(live), ",") != strings.Join(sortedIfnames(rs.Wan), ",") {
		return true
	}
	dns4, dns6 := splitIPs(rs.DNS)
	for _, c := range []struct {
		set  string
		want []string
	}{{qSetDNS4, dns4}, {qSetDNS6, dns6}} {
		live, err := qSetElements(c.set)
		if err != nil {
			return true
		}
		got, _ := splitIPs(live)
		if c.set == qSetDNS6 {
			_, got = splitIPs(live)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			return true
		}
	}
	// The mode is in the forward chain's shape: only "internet" tests the
	// output interface.
	fwd, err := nftRunFn("", "list", "chain", "inet", qTable, qChainForward)
	if err != nil || strings.Contains(string(fwd), "oifname") != (rs.Mode == "internet") {
		return true
	}
	off, err := qSetElements(qSetOff)
	return err != nil || (len(off) > 0) != (st.offRemaining(now) > 0)
}

func qPoll(now time.Time) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return
	}
	qRunDueRestartsLocked(now)
	// Each poll reads the live "seen" set (one nft call). The full check
	// (firewall and DHCP config, interfaces, chains, drift: about a dozen
	// commands) runs every qFullCheckEvery, and at once when the set cannot
	// be read (the firewall lost the feature) or a device was just approved.
	seen, seenErr := qSeenFn()
	full := seenErr != nil || qForceFull || now.Sub(qLastFullCheck) >= qFullCheckEvery
	if !full && st.offRemaining(now) > 0 {
		// A firewall reload empties the kernel-timed pause: put it back
		// now, not at the next full check.
		if off, err := qSetElements(qSetOff); err != nil || len(off) == 0 {
			full = true
		}
	}
	var r qRouter
	live := false
	if full {
		var ok bool
		if r, live, ok = qFullCheckLocked(st, now); !ok {
			return
		}
	}

	// urgent: decisions that change who gets through, written at once.
	// routine: bookkeeping, kept in memory and written at most once per
	// qFlushEvery.
	urgent := false
	if actual := qUserZones(r.actual); full && len(actual) > 0 && strings.Join(actual, ",") != strings.Join(st.Zones, ",") {
		st.Zones = actual
		urgent = true
	}
	if st.Pause.Until != 0 && !st.Pause.active(now) {
		qEndPauseLocked(st)
		urgent = true
	}

	routine := false
	if seenErr == nil {
		u, rt := qRecordSeen(st, seen, now)
		urgent = urgent || u
		routine = routine || rt
	}
	if qPrunePending(st, now) {
		routine = true
	}
	switch {
	case urgent:
		if err := saveQState(st); err != nil {
			// Keep memory in step with what goes live, or the next full
			// check would take the change back out.
			log.Printf("netgrip: quarantine: saving the state: %v", err)
			saveQStateLazy(st)
		}
	case routine:
		saveQStateLazy(st)
	}
	flushQState(now)

	if urgent && !full {
		// A device approved during a learning pause gets through now, not
		// at the next full check.
		var ok bool
		if r, live, ok = qFullCheckLocked(st, now); !ok {
			return
		}
		full = true
	}
	if full && qHasLegacySections(r.sections) {
		// The first release's names: rename everything once.
		if err := qMigrateLocked(st, r); err != nil {
			log.Printf("netgrip: quarantine: renaming the firewall rules: %v", err)
			qFullFailedLocked(now)
		} else {
			log.Printf("netgrip: quarantine: firewall rules renamed to netgrip_quarantine_*")
			qFullFails = 0
		}
		return
	}
	if full && live && qLiveDrifted(st, r, now) {
		if err := qSyncLocked(st, r); err != nil {
			log.Printf("netgrip: quarantine sync: %v", err)
			qFullFailedLocked(now)
			return
		}
	}
	if full && live && !st.Wifi.Enabled {
		qWifiRemoveLeftoversLocked(st)
	}
	if full && live && st.Wifi.Enabled {
		if _, err := qWifiSyncLocked(st, r, now); err != nil {
			log.Printf("netgrip: quarantine Wi-Fi sync: %v", err)
			qFullFailedLocked(now)
			return
		}
	}
	if full {
		qFullFails = 0
	}
}

func qHasLegacySections(sections []string) bool {
	for _, s := range sections {
		if strings.HasPrefix(s, qLegacyPrefix) {
			return true
		}
	}
	return false
}

// qMigrateLocked moves the first release's rules to the current names:
// the include files (checked by nft first) and the UCI sections are
// rewritten and the firewall reloaded, which loads the same approved list
// under the new names. A reload only empties fw4's table, so the old
// chains and sets, unused by then, are deleted afterwards.
func qMigrateLocked(st *qState, r qRouter) error {
	if err := writeQFiles(r.ruleSet(st)); err != nil {
		return err
	}
	if err := applyQIncludes(qIncludeOps(r.sections, r.actual)); err != nil {
		return err
	}
	if err := qVerifyLive(r.actual, ""); err != nil {
		return err
	}
	qDeleteLegacyObjects()
	return nftApply(qOffPauseScript(st.offRemaining(time.Now())))
}

// qLegacyChains and qLegacySets are the first release's nft names.
var (
	qLegacyChains = []string{"netgrip_q_input", "netgrip_q_forward"}
	qLegacySets   = []string{"netgrip_q_ok", "netgrip_q_seen", "netgrip_q_wan", "netgrip_q_private4",
		"netgrip_q_private6", "netgrip_q_dns4", "netgrip_q_dns6", "netgrip_q_off"}
)

// qDeleteLegacyObjects removes them, chains first (a set in use cannot
// go). One at a time and best effort: one already gone stops nothing.
func qDeleteLegacyObjects() {
	for _, c := range qLegacyChains {
		_, _ = nftRunFn("", "delete", "chain", "inet", qTable, c)
	}
	for _, set := range qLegacySets {
		_, _ = nftRunFn("", "delete", "set", "inet", qTable, set)
	}
}

// qFullFailedLocked retries a failed full check on the next poll once;
// a failure that persists falls back to the normal pace (and log rate).
func qFullFailedLocked(now time.Time) {
	qFullFails++
	qLastFullCheck = now
	qForceFull = qFullFails == 1
}

// qFullCheckLocked reads the router and notices a firewall that no longer
// has the feature. ok is false when the poll should stop here: the read
// failed (which decides nothing) or the feature is missing.
func qFullCheckLocked(st *qState, now time.Time) (r qRouter, live, ok bool) {
	r, err := readQRouter()
	if err != nil {
		qFullFailedLocked(now)
		return r, false, false
	}
	qLastFullCheck, qForceFull = now, false
	live = qLiveChainsPresent()
	if len(r.sections) == 0 && !live {
		// Reverted by the confirm window, or removed by hand: once the
		// firewall has neither the sections nor the chains, the feature is
		// off. Twice in a row, so one odd read does not turn it off.
		qMissingPolls++
		if qMissingPolls >= qMissingToRevert {
			log.Printf("netgrip: the firewall no longer has the quarantine (reverted or removed); recording it as off")
			// Without phase 1 nobody could approve a device: the SSIDs get
			// their own networks back (a confirm revert already did that).
			if err := qWifiTeardownLocked(st); err != nil {
				log.Printf("netgrip: quarantine: removing the Wi-Fi layer: %v", err)
			}
			st.Enabled = false
			st.Pause = QPause{}
			_ = saveQState(st)
			removeQFiles()
			qMissingPolls = 0
		}
		return r, false, false
	}
	qMissingPolls = 0
	return r, live, true
}

// qRecordSeen folds the live "seen" set into the state: it approves new
// devices during a learning pause and records and announces the rest.
// urgent: a device was approved (written at once); routine: only the
// pending list or the announcements changed.
func qRecordSeen(st *qState, seen []qElem, now time.Time) (urgent, routine bool) {
	learning := st.Pause.active(now) && st.Pause.Kind == "learn"
	// During a pause "off" nothing is refused: record, but announce only
	// once enforcement is back (the poller then sees them again).
	quiet := st.offRemaining(now) > 0
	excluded := map[string]bool{}
	for _, m := range st.Pause.Excluded {
		excluded[m] = true
	}
	var ident *qIdent
	var announce []QDevice
	for _, e := range seen {
		mac := strings.ToLower(e.Val)
		if !reMac.MatchString(mac) {
			continue
		}
		if _, ok := st.Approved[mac]; ok {
			continue
		}
		_, waiting := st.Pending[mac]
		if learning && !waiting && !excluded[mac] && len(st.Pause.Learned) < qMaxLearned {
			st.Approved[mac] = QApproved{At: now.Unix(), Via: "pause"}
			st.Pause.Learned = append(st.Pause.Learned, mac)
			urgent = true
			continue
		}
		if ident == nil {
			i := qIdentities()
			ident = &i
		}
		d := ident.device(mac)
		p := st.Pending[mac]
		if !waiting {
			p.FirstSeen = now.Unix()
			routine = true
		}
		last := now.Unix()
		if e.Expires > 0 && e.Expires <= qSeenTimeout {
			last = now.Unix() - (qSeenTimeout - e.Expires)
		}
		if last > p.LastSeen {
			p.LastSeen = last
			routine = true
		}
		if d.IP != "" && d.IP != p.IP {
			p.IP = d.IP
			routine = true
		}
		if d.Hostname != "" && d.Hostname != p.Hostname {
			p.Hostname = d.Hostname
			routine = true
		}
		st.Pending[mac] = p
		if _, done := st.Notified[mac]; !done && !quiet {
			st.Notified[mac] = now.Unix()
			routine = true
			d.IP, d.Hostname = p.IP, p.Hostname
			announce = append(announce, d)
		}
	}
	if len(announce) > 0 {
		announce = qNotifyBudget(announce, now)
		for _, d := range announce {
			// A device announced on its own is written at once, so a
			// restart neither repeats the notice nor lets a learning
			// pause approve a device that was already waiting. The
			// budget bounds these writes.
			if d.MAC != "" {
				urgent = true
			}
		}
		go qNotifyPendingBatch(announce, qChannelsFn, qNotifyFn)
	}
	return urgent, routine
}

// qPrunePending drops entries not seen for a week, caps the list (oldest
// first, the MAC breaking ties) and forgets old announcements.
func qPrunePending(st *qState, now time.Time) bool {
	changed := false
	for mac, p := range st.Pending {
		if now.Unix()-p.LastSeen > int64(qPendingTTL/time.Second) {
			delete(st.Pending, mac)
			changed = true
		}
	}
	if len(st.Pending) > qMaxPending {
		macs := make([]string, 0, len(st.Pending))
		for m := range st.Pending {
			macs = append(macs, m)
		}
		sort.Slice(macs, func(i, j int) bool {
			a, b := st.Pending[macs[i]].LastSeen, st.Pending[macs[j]].LastSeen
			if a != b {
				return a < b
			}
			return macs[i] < macs[j]
		})
		for _, m := range macs[:len(macs)-qMaxPending] {
			delete(st.Pending, m)
		}
		changed = true
	}
	for mac, at := range st.Notified {
		if now.Unix()-at > int64(qNotifiedTTL/time.Second) {
			delete(st.Notified, mac)
			changed = true
		}
	}
	if len(st.Notified) > qMaxNotified {
		macs := make([]string, 0, len(st.Notified))
		for m := range st.Notified {
			macs = append(macs, m)
		}
		sort.Slice(macs, func(i, j int) bool {
			if st.Notified[macs[i]] != st.Notified[macs[j]] {
				return st.Notified[macs[i]] < st.Notified[macs[j]]
			}
			return macs[i] < macs[j]
		})
		for _, m := range macs[:len(macs)-qMaxNotified] {
			delete(st.Notified, m)
		}
		changed = true
	}
	return changed
}

// qNotifyBudget limits announcements to qNotifyPerHour an hour: a flood of
// random MACs produces one "more devices" summary, not a stream. Returns
// the devices to announce one by one; the rest are counted into a summary
// device with an empty MAC.
func qNotifyBudget(devs []QDevice, now time.Time) []QDevice {
	if now.Sub(qBudgetStart) >= time.Hour {
		qBudgetStart, qBudgetUsed, qBudgetSummaries = now, 0, 0
	}
	n := qNotifyPerHour - qBudgetUsed
	if n > qNotifyPerPoll {
		n = qNotifyPerPoll
	}
	if n < 0 {
		n = 0
	}
	if n > len(devs) {
		n = len(devs)
	}
	qBudgetUsed += n
	out := append([]QDevice(nil), devs[:n]...)
	if rest := len(devs) - n; rest > 0 && qBudgetSummaries < qSummariesPerHour {
		qBudgetSummaries++
		out = append(out, QDevice{Name: fmt.Sprint(rest)})
	}
	return out
}

// ---- Notifications ----

func qDeviceLabel(d QDevice) string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Hostname != "":
		return d.Hostname
	case d.Vendor != "":
		return d.Vendor + " device"
	case d.Random:
		return "Device with a private (random) MAC"
	}
	return "Unknown device"
}

var (
	qNotifyFn   = notifyAll
	qChannelsFn = anyChannelEnabled
)

// qNotifyPendingBatch announces new quarantined devices: up to
// qNotifyPerPoll one by one, the rest in one summary, so a burst of MACs
// cannot flood the channels. The channel check and sender are passed in
// (not read from the package vars) because this runs on its own goroutine.
func qNotifyPendingBatch(devs []QDevice, channels func() bool, notify func(string, string, string, bool)) {
	if !channels() {
		return
	}
	for _, d := range devs {
		if d.MAC == "" { // a summary (see qNotifyBudget)
			notify("NetGrip",
				fmt.Sprintf("🔒 <b>NetGrip</b>\n%s more new devices were quarantined. See the panel's Quarantine page.", htmlEsc(d.Name)),
				fmt.Sprintf("🔒 NetGrip\n%s more new devices were quarantined. See the panel's Quarantine page.", d.Name),
				false)
			continue
		}
		label := qDeviceLabel(d)
		extra := ""
		if d.IP != "" {
			extra = " · " + d.IP
		}
		notify("NetGrip",
			fmt.Sprintf("🔒 <b>NetGrip</b>\nNew device quarantined: <b>%s</b>\nMAC: %s%s\nApprove it on the panel's Quarantine page.", htmlEsc(label), d.MAC, htmlEsc(extra)),
			fmt.Sprintf("🔒 NetGrip\nNew device quarantined: %s\nMAC: %s%s\nApprove it on the panel's Quarantine page.", label, d.MAC, extra),
			false)
	}
}

func qNotifyLearned(macs []string, channels func() bool, notify func(string, string, string, bool)) {
	if !channels() || len(macs) == 0 {
		return
	}
	list := strings.Join(macs, ", ")
	notify("NetGrip",
		fmt.Sprintf("🔓 <b>NetGrip</b>\nThe quarantine pause ended. %d device(s) joined and were approved: %s", len(macs), htmlEsc(list)),
		fmt.Sprintf("🔓 NetGrip\nThe quarantine pause ended. %d device(s) joined and were approved: %s", len(macs), list),
		false)
}
