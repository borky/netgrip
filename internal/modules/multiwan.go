// multiwan.go — the internet connections this router has, and which one is
// carrying traffic.
//
// OpenWrt can fail over or share load between several uplinks, but only
// through mwan3, whose model is members, policies, metrics and weights. A
// user does not think in those terms; they think "this one, and that one if
// it dies". This module reads the uplinks whether or not mwan3 is installed
// — they exist either way — and, when it is, reports the shape of its config
// in those two words.
//
// Nothing here keys on the name "wan". On a router with a fibre line and a
// cellular backup, the interface literally named "wan" is routinely the
// standby one.
package modules

import (
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// wanProtos are the protocols an uplink is configured with. Everything else
// — bridges, tunnels, the IPv6 side of a link — is not something to fail
// over between.
var wanProtos = map[string]bool{
	"dhcp": true, "static": true, "pppoe": true, "pppoa": true,
	"qmi": true, "ncm": true, "mbim": true, "wwan": true,
	"modemmanager": true, "3g": true, "pptp": true, "l2tp": true,
}

// meteredProtos are the mobile-broadband protocols. Traffic sent over one
// of these usually costs money, which decides whether it may carry load by
// default.
var meteredProtos = map[string]bool{
	"qmi": true, "ncm": true, "mbim": true, "wwan": true,
	"modemmanager": true, "3g": true,
}

// defaultTrackIPs are the addresses a link is pinged at to decide whether it
// is really up. Two well-known public resolvers on separate networks: the
// gateway alone would call a link healthy while the ISP behind it is down.
// Editable per uplink.
var defaultTrackIPs = []string{"1.1.1.1", "9.9.9.9"}

// Section names netgrip owns. mwan3 requires an interface section to be
// named exactly after the network interface, so those cannot be prefixed and
// carry a marker option instead.
const (
	mwanPkg          = "mwan3"
	mwanPrefix       = "netgrip_"
	mwanMemberPrefix = "netgrip_member_"
	mwanPolicyName   = "netgrip_policy_default"
	mwanRuleName     = "netgrip_rule_default"
	mwanManagedOpt   = "netgrip_managed"
	mwanDisabledOpt  = "netgrip_disabled"
	mwanWanMarker    = "netgrip_wan"
)

// Modes. "custom" is a config that works but is not one of the two shapes
// netgrip writes — a hand-written one, typically — and is never silently
// overwritten.
const (
	MWModeOff      = "off"
	MWModeFailover = "failover"
	MWModeBalance  = "balance"
	MWModeCustom   = "custom"
)

// WanCandidate is one internet connection as the panel presents it.
type WanCandidate struct {
	Name     string `json:"name"` // UCI network section, and the mwan3 section name
	Proto    string `json:"proto"`
	Device   string `json:"device,omitempty"`
	L3Device string `json:"l3_device,omitempty"`
	Port     string `json:"port,omitempty"` // physical port, when it has one
	Up       bool   `json:"up"`
	// Active: carrying traffic right now.
	Active bool `json:"active"`
	// Primary: the preferred uplink in failover mode.
	Primary bool `json:"primary"`
	// Online/Tracking come from mwan3 when it runs; empty otherwise.
	Online   string   `json:"online,omitempty"`
	Tracking string   `json:"tracking,omitempty"`
	SharePct int      `json:"share_pct"`
	IPv4     []string `json:"ipv4"`
	Gateway  string   `json:"gateway,omitempty"`
	Metric   int      `json:"metric"`
	Uptime   int64    `json:"uptime"`
	Weight   int      `json:"weight"`
	Balance  bool     `json:"balance"`
	Metered  bool     `json:"metered"`
	Managed  bool     `json:"managed"`
	Track    []string `json:"track"`
	// Reason records which signal qualified this interface, so a surprising
	// list can be explained instead of argued with.
	Reason string `json:"reason"` // zone|route|marker
}

// MultiWanProbe is the whole read-only picture for one poll.
type MultiWanProbe struct {
	Applicable       bool           `json:"applicable"`
	Candidates       []WanCandidate `json:"candidates"`
	MultiWanPossible bool           `json:"multi_wan_possible"`
	Installed        bool           `json:"installed"`
	Enabled          bool           `json:"enabled"`
	Running          bool           `json:"running"`
	Mode             string         `json:"mode"`
	Managed          bool           `json:"managed"`
	Foreign          bool           `json:"foreign"`
	ForeignSections  []string       `json:"foreign_sections"`
	PrimaryIface     string         `json:"primary_iface,omitempty"`
	ActivePolicy     string         `json:"active_policy,omitempty"`
	DefaultTrack     []string       `json:"default_track"`
	PackageID        string         `json:"package_id"`
	ConfigPresent    bool           `json:"config_present"`
}

// ---------------------------------------------------------------------------
// Discovery (pure)
// ---------------------------------------------------------------------------

// classifyWanCandidates decides which interfaces are internet uplinks.
//
// The rules, in order: it must have a UCI interface section (which excludes
// every interface netifd invented at runtime), it must not be one of those
// runtime children, its protocol must be one an uplink uses, it must not sit
// on the LAN, and something must actually suggest it faces the internet — a
// masquerading zone, a default route, or an explicit marker.
//
// Runtime children are then folded into their parent: on a modem uplink the
// address and the route belong to a child interface that cannot be
// configured, so its facts are reported under the name that can.
func classifyWanCandidates(
	netSections map[string]uciSection,
	zones []FWZone,
	dump []ubus.InterfaceState,
	lanDevices []string,
) []WanCandidate {
	byName := map[string]ubus.InterfaceState{}
	for _, s := range dump {
		byName[s.Name] = s
	}
	zoneNets := internetZoneNetworks(zones)

	out := []WanCandidate{}
	for name, sec := range netSections {
		if sec.Type != "interface" {
			continue
		}
		state := byName[name]
		if state.Dynamic {
			continue
		}
		proto := sec.Option("proto")
		if proto == "" {
			proto = state.Proto
		}
		if !wanProtos[proto] {
			continue
		}
		c := WanCandidate{
			Name:     name,
			Proto:    proto,
			Device:   firstNonBlank(state.Device, sec.Option("device")),
			L3Device: state.L3Device,
			Up:       state.Up,
			IPv4:     append([]string{}, state.IPv4...),
			Gateway:  state.Gateway,
			Uptime:   state.Uptime,
			Metric:   routeCost(state),
			Metered:  meteredProtos[proto],
			Weight:   1,
			Track:    []string{},
		}
		hasRoute := state.HasDefaultRoute
		// Fold in whatever netifd spawned underneath this interface.
		for _, child := range dump {
			if !child.Dynamic || child.Name == name || child.L3Device == "" || child.L3Device != state.L3Device {
				continue
			}
			if len(c.IPv4) == 0 {
				c.IPv4 = append([]string{}, child.IPv4...)
			}
			if c.Gateway == "" {
				c.Gateway = child.Gateway
			}
			if c.Uptime == 0 {
				c.Uptime = child.Uptime
			}
			if child.HasDefaultRoute && !hasRoute {
				hasRoute = true
				c.Metric = routeCost(child)
			}
			c.Up = c.Up || child.Up
		}
		if isLANDevice(c.L3Device, lanDevices) || isLANDevice(c.Device, lanDevices) {
			continue
		}
		switch {
		case sec.Option(mwanWanMarker) == "1":
			c.Reason = "marker"
		case zoneNets[name]:
			c.Reason = "zone"
		case hasRoute:
			c.Reason = "route"
		default:
			continue
		}
		c.Port = physicalPort(c.Device)
		c.Active = hasRoute
		out = append(out, c)
	}

	// Several uplinks can hold a default route at once; the kernel uses the
	// cheapest, so only that one is actually carrying traffic.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	best := -1
	for i := range out {
		if !out[i].Active {
			continue
		}
		if best < 0 || out[i].Metric < out[best].Metric {
			best = i
		}
	}
	for i := range out {
		out[i].Active = i == best
	}
	return out
}

// internetZoneNetworks lists the networks of every zone that both
// masquerades and does not forward freely — the shape of a zone facing the
// internet. A VPN zone masquerades too, but the interfaces in it never pass
// the protocol test, so it contributes nothing.
func internetZoneNetworks(zones []FWZone) map[string]bool {
	nets := map[string]bool{}
	for _, z := range zones {
		if !z.Masq || strings.EqualFold(z.Forward, "ACCEPT") {
			continue
		}
		for _, n := range z.Network {
			nets[n] = true
		}
	}
	return nets
}

// routeCost is what orders two default routes. Interfaces without one sort
// last, which keeps them out of the "active" comparison.
func routeCost(s ubus.InterfaceState) int {
	if !s.HasDefaultRoute {
		return 1 << 30
	}
	if s.RouteMetric > 0 {
		return s.RouteMetric
	}
	return s.Metric
}

var reVLANSuffix = regexp.MustCompile(`\.\d+$`)

// physicalPort is the socket an uplink is plugged into, when it has one at
// all: a modem reports a character device, and a VLAN-tagged uplink reports
// the port with its tag appended.
func physicalPort(dev string) string {
	if dev == "" || strings.HasPrefix(dev, "/dev/") || strings.HasPrefix(dev, "br-") {
		return ""
	}
	return reVLANSuffix.ReplaceAllString(dev, "")
}

func isLANDevice(dev string, lanDevices []string) bool {
	if dev == "" {
		return false
	}
	for _, l := range lanDevices {
		if l == "" {
			continue
		}
		// A VLAN of the LAN bridge is still the LAN.
		if dev == l || strings.HasPrefix(dev, l+".") {
			return true
		}
	}
	return false
}

// uciListParts splits the values of a list option. `uci show` prints a whole
// list on one line (key='a' 'b' 'c'), and the generic parser only strips the
// outermost quotes, so four tracking addresses arrive as one string.
func uciListParts(vals []string) []string {
	out := []string{}
	for _, v := range vals {
		for _, part := range strings.Split(v, "' '") {
			if p := strings.TrimSpace(strings.Trim(part, "'")); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Reading the mwan3 config (pure)
// ---------------------------------------------------------------------------

// mwanConfig is what the config says, independently of what is running.
type mwanConfig struct {
	Mode    string
	Primary string
	Managed bool
	Foreign []string
	// Members maps an mwan3 member section to its interface, metric and weight.
	Members map[string]mwanMember
	// Ifaces lists the interface sections, whether netgrip wrote them and
	// what they track.
	Ifaces map[string]mwanIface
}

type mwanMember struct {
	Section   string
	Interface string
	Metric    int
	Weight    int
	Ours      bool
}

type mwanIface struct {
	Enabled bool
	Ours    bool
	Track   []string
}

// readMwanConfig interprets `uci show mwan3`. The mode is inferred from the
// members rather than stored: a config edited elsewhere then describes
// itself honestly instead of claiming whatever netgrip last wrote.
func readMwanConfig(show string) mwanConfig {
	cfg := mwanConfig{
		Mode:    MWModeOff,
		Members: map[string]mwanMember{},
		Ifaces:  map[string]mwanIface{},
		Foreign: []string{},
	}
	ours, foreign := 0, 0
	for name, sec := range parseUCIShow(show, mwanPkg) {
		isOurs := strings.HasPrefix(name, mwanPrefix)
		switch sec.Type {
		case "interface":
			cfg.Ifaces[name] = mwanIface{
				Enabled: sec.Option("enabled") != "0",
				Ours:    sec.Option(mwanManagedOpt) == "1",
				Track:   uciListParts(sec.Options["track_ip"]),
			}
		case "member":
			m := mwanMember{Section: name, Interface: sec.Option("interface"), Ours: isOurs}
			m.Metric, _ = strconv.Atoi(sec.Option("metric"))
			m.Weight, _ = strconv.Atoi(sec.Option("weight"))
			if m.Weight == 0 {
				m.Weight = 1
			}
			cfg.Members[name] = m
			if isOurs {
				ours++
			} else {
				foreign++
				cfg.Foreign = append(cfg.Foreign, name)
			}
		case "policy", "rule":
			if isOurs {
				ours++
			} else {
				foreign++
				cfg.Foreign = append(cfg.Foreign, name)
			}
		}
	}
	sort.Strings(cfg.Foreign)
	cfg.Managed = ours > 0 && foreign == 0
	cfg.Mode, cfg.Primary = mwanModeFrom(cfg.Members)
	if cfg.Mode == MWModeOff && foreign > 0 {
		cfg.Mode = MWModeCustom
	}
	return cfg
}

// mwanModeFrom reads the two modes out of member metrics. mwan3 only uses
// the members in the lowest metric group that has a link online, so several
// members sharing the lowest metric means they share traffic, and one alone
// at the lowest metric means the others are standby.
func mwanModeFrom(members map[string]mwanMember) (mode, primary string) {
	lowest, count, first := 0, 0, ""
	for _, m := range members {
		if !m.Ours || m.Interface == "" {
			continue
		}
		switch {
		case count == 0 || m.Metric < lowest:
			lowest, count, first = m.Metric, 1, m.Interface
		case m.Metric == lowest:
			count++
			if m.Interface < first {
				first = m.Interface
			}
		}
	}
	if count == 0 {
		return MWModeOff, ""
	}
	if count > 1 {
		return MWModeBalance, ""
	}
	return MWModeFailover, first
}

// ---------------------------------------------------------------------------
// Reading what mwan3 is doing right now (pure)
// ---------------------------------------------------------------------------

type mwanLive struct {
	Online   string // online|offline|unknown
	Tracking string // active|down
}

var reMwanIface = regexp.MustCompile(`^\s*interface (\S+) is (\w+) and tracking is (\w+)`)

// parseMwanInterfaces reads `mwan3 interfaces`, which is the only place the
// tracker's own verdict on a link is published.
func parseMwanInterfaces(out string) map[string]mwanLive {
	res := map[string]mwanLive{}
	for _, line := range strings.Split(out, "\n") {
		m := reMwanIface.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		res[m[1]] = mwanLive{Online: m[2], Tracking: m[3]}
	}
	return res
}

var reMwanShare = regexp.MustCompile(`^\s+(\S+)\s+\((\d+)%\)`)

// parseMwanPolicies reads `mwan3 policies`. Under mwan3 the route table no
// longer says where traffic goes — the marks do — so this is the only honest
// source for "which uplink is carrying it", and it is per address family.
func parseMwanPolicies(out string) (policy string, shares map[string]int) {
	shares = map[string]int{}
	inV4 := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Current ipv4 policies"):
			inV4 = true
			continue
		case strings.HasPrefix(trimmed, "Current ipv6 policies"):
			inV4 = false
			continue
		}
		if !inV4 || trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			if policy == "" {
				policy = strings.TrimSuffix(trimmed, ":")
			}
			continue
		}
		if m := reMwanShare.FindStringSubmatch(line); m != nil {
			pct, _ := strconv.Atoi(m[2])
			shares[m[1]] = pct
		}
	}
	return policy, shares
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

// buildMultiWanProbe assembles the probe from already-gathered inputs, so
// every state — including "mwan3 is not installed" — is reachable in a test
// without a router.
func buildMultiWanProbe(
	candidates []WanCandidate,
	installed, enabled, running, configPresent bool,
	cfg mwanConfig,
	live map[string]mwanLive,
	activePolicy string,
	shares map[string]int,
) *MultiWanProbe {
	p := &MultiWanProbe{
		Applicable:       len(candidates) > 0,
		Candidates:       candidates,
		MultiWanPossible: len(candidates) >= 2,
		Installed:        installed,
		Enabled:          enabled,
		Running:          running,
		Mode:             MWModeOff,
		DefaultTrack:     defaultTrackIPs,
		PackageID:        mwanPkg,
		ConfigPresent:    configPresent,
		ForeignSections:  []string{},
	}
	// A removed package leaves its config behind. Offering modes for a
	// service that cannot run would be a lie.
	if !installed {
		return p
	}
	p.Mode = cfg.Mode
	p.Managed = cfg.Managed
	p.Foreign = len(cfg.Foreign) > 0
	p.ForeignSections = cfg.Foreign
	p.PrimaryIface = cfg.Primary
	p.ActivePolicy = activePolicy

	for i := range p.Candidates {
		c := &p.Candidates[i]
		if l, ok := live[c.Name]; ok {
			c.Online, c.Tracking = l.Online, l.Tracking
		}
		if ifc, ok := cfg.Ifaces[c.Name]; ok {
			c.Managed = ifc.Ours
			if len(ifc.Track) > 0 {
				c.Track = ifc.Track
			}
		}
		if len(c.Track) == 0 {
			c.Track = defaultTrackIPs
		}
		for _, m := range cfg.Members {
			if m.Interface != c.Name || !m.Ours {
				continue
			}
			c.Weight = m.Weight
			c.Primary = cfg.Mode == MWModeFailover && m.Interface == cfg.Primary
			c.Balance = cfg.Mode == MWModeBalance && m.Metric == lowestOurMetric(cfg.Members)
		}
		// Once mwan3 publishes a distribution it outranks the route table,
		// and it outranks it for every uplink: one missing from the list is
		// one carrying nothing, however its route looks.
		if len(shares) > 0 {
			c.SharePct = shares[c.Name]
			c.Active = c.SharePct > 0
		}
	}
	return p
}

func lowestOurMetric(members map[string]mwanMember) int {
	lowest, found := 0, false
	for _, m := range members {
		if !m.Ours {
			continue
		}
		if !found || m.Metric < lowest {
			lowest, found = m.Metric, true
		}
	}
	return lowest
}

// wanCandidates gathers the live inputs and runs the classifier.
func wanCandidates() []WanCandidate {
	show, err := uciShowNetwork()
	if err != nil {
		return []WanCandidate{}
	}
	dump, err := ubus.DumpInterfaces()
	if err != nil {
		dump = []ubus.InterfaceState{}
	}
	zones := []FWZone{}
	if out, err := exec.Command("uci", "show", "firewall").Output(); err == nil {
		zones = parseFWZonesFrom(string(out))
	}
	return classifyWanCandidates(parseUCIShow(show, "network"), zones, dump, []string{LANDevice(), LANBridge()})
}

// ProbeMultiWAN reports the uplinks and, when mwan3 is installed, what it is
// doing with them.
func ProbeMultiWAN() *MultiWanProbe {
	candidates := wanCandidates()
	installed := pkgInstalled(mwanPkg)
	cfg := mwanConfig{Mode: MWModeOff, Members: map[string]mwanMember{}, Ifaces: map[string]mwanIface{}, Foreign: []string{}}
	live := map[string]mwanLive{}
	policy, shares := "", map[string]int{}
	configPresent := false

	if out, err := exec.Command("uci", "show", mwanPkg).Output(); err == nil {
		configPresent = strings.TrimSpace(string(out)) != ""
		cfg = readMwanConfig(string(out))
	}
	running := installed && executor.ServiceRunning(mwanPkg)
	if running {
		if out, err := exec.Command(mwanPkg, "interfaces").Output(); err == nil {
			live = parseMwanInterfaces(string(out))
		}
		if out, err := exec.Command(mwanPkg, "policies").Output(); err == nil {
			policy, shares = parseMwanPolicies(string(out))
		}
	}
	return buildMultiWanProbe(candidates, installed, installed && executor.ServiceEnabled(mwanPkg),
		running, configPresent, cfg, live, policy, shares)
}
