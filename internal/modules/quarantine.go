package modules

// Device quarantine: state, API and the background poller. See
// quarantine_nft.go for how it hooks into the firewall.
//
// A device NetGrip has not been told to trust gets, at most, the internet
// ("internet" mode) or nothing beyond an address and DNS ("nothing" mode),
// in the zones the user chose to protect. Everything about the router's
// layout (zones, their networks, the WAN interfaces) is read at runtime from
// its own configuration, so the feature works on any firewall4 router.
//
// Lockout safety:
//   - enabling needs a baseline: the devices to trust, and always the device
//     the panel is used from;
//   - the generated rules are validated by the kernel (nft -c) before the
//     firewall loads them;
//   - the server runs enabling (and zone changes) inside the confirm window,
//     so a lost panel reverts by itself;
//   - after a revert the include sections are gone; the poller notices and
//     records the feature as off.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	qMaxPause       = 24 * time.Hour
	qPollInterval   = 5 * time.Second
	qLearnPollEvery = 2 * time.Second
)

var qMu sync.Mutex

// QApproved is one trusted device.
type QApproved struct {
	Name string `json:"name,omitempty"`
	At   int64  `json:"at"`
	// Via: "baseline" (trusted when enabling), "manual", "pause" (joined
	// during a learning pause).
	Via string `json:"via"`
}

// QPending is a device seen in quarantine.
type QPending struct {
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	IP        string `json:"ip,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Notified  bool   `json:"notified,omitempty"`
}

// QPause is a time-limited pause. Kind "learn": still enforced, but every
// new device is approved automatically. Kind "off": nothing is enforced.
type QPause struct {
	Until   int64    `json:"until,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	Learned []string `json:"learned,omitempty"`
}

func (p QPause) active(now time.Time) bool { return p.Until > now.Unix() }

type qState struct {
	Enabled  bool                 `json:"enabled"`
	Mode     string               `json:"mode"`
	Zones    []string             `json:"zones"`
	Approved map[string]QApproved `json:"approved"`
	Pending  map[string]QPending  `json:"pending"`
	Pause    QPause               `json:"pause"`
	// WanApplied is the WAN interface list last written, to notice changes.
	WanApplied []string `json:"wan_applied,omitempty"`
}

func loadQState() *qState {
	st := &qState{Mode: "internet", Approved: map[string]QApproved{}, Pending: map[string]QPending{}}
	if raw, err := os.ReadFile(qStatePath); err == nil {
		_ = json.Unmarshal(raw, st)
	}
	if st.Approved == nil {
		st.Approved = map[string]QApproved{}
	}
	if st.Pending == nil {
		st.Pending = map[string]QPending{}
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
	return writeFileAtomic(qStatePath, raw)
}

func (st *qState) approvedMACs() []string {
	out := make([]string, 0, len(st.Approved))
	for m := range st.Approved {
		out = append(out, m)
	}
	return sortedMACs(out)
}

func (st *qState) ruleSet(wan []string, now time.Time) qRuleSet {
	return qRuleSet{
		Mode:     st.Mode,
		Paused:   st.Pause.active(now) && st.Pause.Kind == "off",
		Approved: st.approvedMACs(),
		Wan:      wan,
	}
}

// ---- Zones and WAN interfaces, from the router's own configuration ----

// QZone is a firewall zone as the quarantine sees it.
type QZone struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	// Wan: the zone masquerades, i.e. it is an upstream. Never protectable.
	Wan bool `json:"wan"`
	// Suggested: a client zone (not WAN, serves DHCP on one of its networks).
	Suggested bool `json:"suggested"`
	Protected bool `json:"protected"`
}

var reZoneName = regexp.MustCompile(`^[a-zA-Z_.][a-zA-Z0-9_.-]*$`)

// qZoneDevices reads the `device` option of every zone (zones can name
// devices directly instead of, or besides, networks).
func qZoneDevices(uciFirewall string) map[string][]string {
	names := map[string]string{} // section -> zone name
	devs := map[string][]string{}
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
		switch opt {
		case "name":
			names[sec] = strings.Trim(val, "'")
		case "device":
			devs[sec] = append(devs[sec], uciListValues(line)...)
		}
	}
	out := map[string][]string{}
	for sec, d := range devs {
		if n := names[sec]; n != "" {
			out[n] = d
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

// qZonesFrom builds the zone list from `uci show firewall` and
// `uci show dhcp`. Pure, for tests.
func qZonesFrom(uciFirewall, uciDhcp string, protected []string) []QZone {
	served := dhcpServedNetworks(uciDhcp)
	prot := map[string]bool{}
	for _, z := range protected {
		prot[z] = true
	}
	out := []QZone{}
	for _, z := range parseFWZonesFrom(uciFirewall) {
		q := QZone{Name: z.Name, Networks: z.Network, Wan: z.Masq, Protected: prot[z.Name]}
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

// qWanDevicesFrom resolves the WAN-side interface names: every device of
// every masquerading zone, from its networks' runtime state and its own
// `device` list. Pure, for tests.
func qWanDevicesFrom(zones []QZone, zoneDevs map[string][]string, ifaces []ubus.InterfaceState) []string {
	byName := map[string]ubus.InterfaceState{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	out := []string{}
	for _, z := range zones {
		if !z.Wan {
			continue
		}
		for _, n := range z.Networks {
			if i, ok := byName[n]; ok {
				for _, d := range []string{i.L3Device, i.Device} {
					if d != "" && !strings.HasPrefix(d, "/") {
						out = append(out, d)
					}
				}
			}
		}
		out = append(out, zoneDevs[z.Name]...)
	}
	return sortedIfnames(out)
}

var (
	// Uncached on purpose: right after its own UCI change the feature must
	// see the new sections, and the shared read cache lags by up to 2s.
	uciShowFn = func(pkg string) string {
		out, err := uciExec("show", pkg)
		if err != nil {
			return ""
		}
		return string(out)
	}
	dumpInterfacesFn = func() []ubus.InterfaceState { i, _ := ubus.DumpInterfaces(); return i }
)

func qCurrentZones(protected []string) []QZone {
	return qZonesFrom(uciShowFn("firewall"), uciShowFn("dhcp"), protected)
}

func qCurrentWan() []string {
	fw := uciShowFn("firewall")
	return qWanDevicesFrom(qZonesFrom(fw, "", nil), qZoneDevices(fw), dumpInterfacesFn())
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
		if sec != key && !strings.Contains(sec, ".") && strings.HasPrefix(sec, qSectionPrefix) {
			out = append(out, sec)
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
			add(fmt.Sprintf("%s_in_%d", qSectionPrefix, i), qInputFile(), "chain-prepend", "input_"+z)
			add(fmt.Sprintf("%s_fw_%d", qSectionPrefix, i), qForwardFile(), "chain-prepend", "forward_"+z)
		}
	}
	return append(ops,
		executor.Op{Kind: "uci_commit", Args: []string{"firewall"}},
		executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}},
	)
}

func qIncludesConfigured() bool { return uciSectionExists("firewall." + qSectionTable) }

// applyQIncludes is a seam: it runs the UCI ops (tests record them).
var applyQIncludes = func(ops []executor.Op) error { return executor.Apply(ops, nil) }

// qVerifyLive checks the actual result of an enable: chains loaded, every
// protected zone jumps into them, and the must-keep MAC is in the set.
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
	if mustKeep != "" {
		elems, err := qSetElements(qSetOK)
		if err != nil {
			return err
		}
		for _, e := range elems {
			if e == mustKeep {
				return nil
			}
		}
		return fmt.Errorf("your device %s is not in the live approved set", mustKeep)
	}
	return nil
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

// QuarantineProbe is the API view. Enabled is the intent; Active is what
// the firewall actually runs.
type QuarantineProbe struct {
	Applicable bool      `json:"applicable"`
	Reason     string    `json:"reason,omitempty"`
	Enabled    bool      `json:"enabled"`
	Active     bool      `json:"active"`
	Mode       string    `json:"mode"`
	Zones      []QZone   `json:"zones"`
	Wan        []string  `json:"wan"`
	Approved   []QDevice `json:"approved"`
	Pending    []QDevice `json:"pending"`
	Pause      QPause    `json:"pause"`
	Issues     []string  `json:"issues"`
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

func probeQuarantineLocked() QuarantineProbe {
	st := loadQState()
	ok, why := qApplicable()
	p := QuarantineProbe{
		Applicable: ok, Reason: why, Enabled: st.Enabled, Mode: st.Mode,
		Zones: []QZone{}, Wan: []string{}, Approved: []QDevice{}, Pending: []QDevice{},
		Pause: st.Pause, Issues: []string{},
	}
	if !ok {
		return p
	}
	p.Zones = qCurrentZones(st.Zones)
	p.Wan = qCurrentWan()
	p.Active = qIncludesConfigured() && qLiveChainsPresent()
	if !p.Pause.active(time.Now()) {
		p.Pause = QPause{}
	}
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
		if st.Mode == "internet" && len(p.Wan) == 0 {
			p.Issues = append(p.Issues, "no WAN interface found: quarantined devices get no internet")
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

// ---- Baseline candidates ----

// QCandidate is a device the enable wizard offers to trust.
type QCandidate struct {
	QDevice
	Sources   []string `json:"sources"`
	Requester bool     `json:"requester,omitempty"`
}

// requesterMACFn resolves the panel user's device MAC from its IP.
var requesterMACFn = func(ip string) string {
	if ip == "" {
		return ""
	}
	for mac, a := range localArp() {
		if a == ip {
			return mac
		}
	}
	out, err := exec.Command("ip", "neigh", "show", "to", ip).Output()
	if err != nil {
		return ""
	}
	return parseNeighMAC(string(out))
}

// parseNeighMAC reads the lladdr of the first resolved `ip neigh` line.
func parseNeighMAC(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" && reMac.MatchString(f[i+1]) {
				return strings.ToLower(f[i+1])
			}
		}
	}
	return ""
}

// QuarantineRequesterMAC is the panel user's MAC, or "".
func QuarantineRequesterMAC(ip string) string { return requesterMACFn(ip) }

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
	// AllowNoRequester: enable even though the panel user's MAC is unknown
	// (panel reached over a VPN or from another network).
	AllowNoRequester bool `json:"allow_no_requester,omitempty"`
}

type QApproveItem struct {
	MAC  string `json:"mac"`
	Name string `json:"name,omitempty"`
}

func validMode(m string) bool { return m == "internet" || m == "nothing" }

// validateZones checks that every zone exists and is not an upstream.
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
		case !reZoneName.MatchString(name) || !ok:
			return nil, fmt.Errorf("unknown zone %q", name)
		case z.Wan:
			return nil, fmt.Errorf("zone %q is an upstream (masquerading) zone and cannot be protected", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
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
	zones, err := validateZones(req.Zones, qCurrentZones(nil))
	if err != nil {
		return probeQuarantineLocked(), err
	}
	requester := requesterMACFn(requesterIP)
	if requester == "" && !req.AllowNoRequester {
		return probeQuarantineLocked(), errors.New("cannot tell which device you are using (no MAC for your address); open the panel from a device on the local network, or confirm you accept the risk")
	}
	now := time.Now()
	st := loadQState()
	st.Mode = req.Mode
	st.Zones = zones
	for _, a := range req.Approve {
		mac := strings.ToLower(strings.TrimSpace(a.MAC))
		if !reMac.MatchString(mac) {
			return probeQuarantineLocked(), fmt.Errorf("invalid MAC %q", a.MAC)
		}
		if _, ok := st.Approved[mac]; !ok {
			st.Approved[mac] = QApproved{Name: qCleanName(a.Name), At: now.Unix(), Via: "baseline"}
		}
		delete(st.Pending, mac)
	}
	if requester != "" {
		if _, ok := st.Approved[requester]; !ok {
			st.Approved[requester] = QApproved{At: now.Unix(), Via: "baseline"}
		}
		delete(st.Pending, requester)
	}
	st.Pause = QPause{}
	wan := qCurrentWan()
	rs := st.ruleSet(wan, now)
	if err := nftCheck(renderQCheck(rs)); err != nil {
		return probeQuarantineLocked(), fmt.Errorf("the kernel rejected the quarantine rules, nothing was changed: %w", err)
	}
	if err := writeQFiles(rs); err != nil {
		return probeQuarantineLocked(), err
	}
	st.Enabled = true
	st.WanApplied = rs.Wan
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if err := applyQIncludes(qIncludeOps(qIncludeSections(uciShowFn("firewall")), zones)); err != nil {
		qDisableLocked(st)
		return probeQuarantineLocked(), fmt.Errorf("applying the firewall change failed and was undone: %w", err)
	}
	if err := qVerifyLive(zones, requester); err != nil {
		qDisableLocked(st)
		return probeQuarantineLocked(), fmt.Errorf("the quarantine did not come up as expected and was turned off again: %w", err)
	}
	log.Printf("netgrip: quarantine enabled (mode %s, zones %s, %d approved)", st.Mode, strings.Join(zones, ","), len(st.Approved))
	return probeQuarantineLocked(), nil
}

// qDisableLocked removes the include sections and files; the approvals are
// kept so turning the feature back on remembers them.
func qDisableLocked(st *qState) error {
	st.Enabled = false
	st.Pause = QPause{}
	_ = saveQState(st)
	var err error
	if secs := qIncludeSections(uciShowFn("firewall")); len(secs) > 0 {
		err = applyQIncludes(qIncludeOps(secs, nil))
	}
	for _, f := range []string{qTableFile(), qInputFile(), qForwardFile()} {
		_ = os.Remove(f)
	}
	return err
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
// server wraps it in the confirm window).
func QuarantineSetZones(zones []string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return probeQuarantineLocked(), errors.New("the quarantine is off")
	}
	z, err := validateZones(zones, qCurrentZones(nil))
	if err != nil {
		return probeQuarantineLocked(), err
	}
	st.Zones = z
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if err := applyQIncludes(qIncludeOps(qIncludeSections(uciShowFn("firewall")), z)); err != nil {
		return probeQuarantineLocked(), err
	}
	return probeQuarantineLocked(), qVerifyLive(z, "")
}

// qSyncLocked writes the include file and updates the live firewall when
// the quarantine is running.
func qSyncLocked(st *qState) error {
	rs := st.ruleSet(qCurrentWan(), time.Now())
	if err := writeQFiles(rs); err != nil {
		return err
	}
	st.WanApplied = rs.Wan
	if !qLiveChainsPresent() {
		return nil
	}
	return nftApply(renderQRuntimeUpdate(rs))
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
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if st.Enabled {
		if err := qSyncLocked(st); err != nil {
			return probeQuarantineLocked(), err
		}
		_ = saveQState(st)
	}
	return probeQuarantineLocked(), nil
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
		if n := qCleanName(it.Name); n != "" {
			a.Name = n
		}
		st.Approved[mac] = a
		delete(st.Pending, mac)
	}
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if st.Enabled {
		if err := qSyncLocked(st); err != nil {
			return probeQuarantineLocked(), err
		}
		_ = saveQState(st)
	}
	return probeQuarantineLocked(), nil
}

// QuarantineRevoke withdraws trust. The panel user's own device is refused:
// that would cut the panel off. Connections already open stay up until they
// end (the firewall only judges new ones).
func QuarantineRevoke(mac, requesterIP string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !reMac.MatchString(mac) {
		return probeQuarantineLocked(), errors.New("invalid MAC")
	}
	if req := requesterMACFn(requesterIP); req != "" && req == mac {
		return probeQuarantineLocked(), errors.New("this is the device you are using: revoking it would cut off your access to the panel")
	}
	st := loadQState()
	if _, ok := st.Approved[mac]; !ok {
		return probeQuarantineLocked(), errors.New("not an approved device")
	}
	delete(st.Approved, mac)
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if st.Enabled {
		if err := qSyncLocked(st); err != nil {
			return probeQuarantineLocked(), err
		}
		_ = saveQState(st)
	}
	return probeQuarantineLocked(), nil
}

// QuarantineForget drops a pending entry (it reappears if the device
// comes back).
func QuarantineForget(mac string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	delete(st.Pending, strings.ToLower(strings.TrimSpace(mac)))
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
	if st.Pause.Kind != kind {
		learned = nil
	}
	st.Pause = QPause{Until: time.Now().Add(d).Unix(), Kind: kind, Learned: learned}
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if err := qSyncLocked(st); err != nil {
		return probeQuarantineLocked(), err
	}
	_ = saveQState(st)
	return probeQuarantineLocked(), nil
}

// QuarantineResume ends a pause now.
func QuarantineResume() (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	qEndPauseLocked(st)
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	if st.Enabled {
		if err := qSyncLocked(st); err != nil {
			return probeQuarantineLocked(), err
		}
		_ = saveQState(st)
	}
	return probeQuarantineLocked(), nil
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
// devices, approves them during a learning pause, ends pauses, follows WAN
// interface changes and notices when the firewall dropped the feature
// (a confirm revert, or the sections removed by hand).
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

var qSeenFn = func() ([]string, error) { return qSetElements(qSetSeen) }

func qPoll(now time.Time) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return
	}
	dirty, resync := false, false

	if !qIncludesConfigured() {
		// Reverted by the confirm window, or removed by hand: the firewall
		// no longer has the feature, so neither does the intent.
		log.Printf("netgrip: quarantine include sections are gone (reverted or removed); recording the feature as off")
		st.Enabled = false
		st.Pause = QPause{}
		_ = saveQState(st)
		return
	}

	if st.Pause.Until != 0 && !st.Pause.active(now) {
		qEndPauseLocked(st)
		dirty, resync = true, true
	}

	wan := qCurrentWan()
	if strings.Join(wan, ",") != strings.Join(sortedIfnames(st.WanApplied), ",") {
		dirty, resync = true, true
	}

	seen, err := qSeenFn()
	if err == nil {
		var ident *qIdent
		learning := st.Pause.active(now) && st.Pause.Kind == "learn"
		for _, mac := range seen {
			if !reMac.MatchString(mac) {
				continue
			}
			if _, ok := st.Approved[mac]; ok {
				continue
			}
			if learning {
				st.Approved[mac] = QApproved{At: now.Unix(), Via: "pause"}
				st.Pause.Learned = append(st.Pause.Learned, mac)
				delete(st.Pending, mac)
				dirty, resync = true, true
				continue
			}
			if ident == nil {
				i := qIdentities()
				ident = &i
			}
			d := ident.device(mac)
			p, existed := st.Pending[mac]
			if !existed {
				p.FirstSeen = now.Unix()
			}
			p.LastSeen = now.Unix()
			if d.IP != "" {
				p.IP = d.IP
			}
			if d.Hostname != "" {
				p.Hostname = d.Hostname
			}
			if !p.Notified {
				p.Notified = true
				go qNotifyPending(d, qChannelsFn, qNotifyFn)
			}
			st.Pending[mac] = p
			dirty = true
		}
	}

	if qPrunePending(st, now) {
		dirty = true
	}
	if resync {
		if err := qSyncLocked(st); err != nil {
			log.Printf("netgrip: quarantine sync: %v", err)
		}
	}
	if dirty {
		_ = saveQState(st)
	}
}

// qPrunePending drops entries not seen for a week and caps the list.
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
		sort.Slice(macs, func(i, j int) bool { return st.Pending[macs[i]].LastSeen < st.Pending[macs[j]].LastSeen })
		for _, m := range macs[:len(macs)-qMaxPending] {
			delete(st.Pending, m)
		}
		changed = true
	}
	return changed
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

// The channel check and sender are passed in (not read from the package
// vars) because this runs on its own goroutine.
func qNotifyPending(d QDevice, channels func() bool, notify func(string, string, string, bool)) {
	if !channels() {
		return
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
