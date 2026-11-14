package modules

// Device quarantine, Wi-Fi layer (phase 2).
//
// The router's own SSIDs in protected zones stop handing every device the
// SSID's network. With the layer on:
//
//   - a quarantine network exists: a bridge with no ports, its own /24,
//     DHCP and a firewall zone that allows DHCP, DNS and time from the
//     router, DNS to the resolvers DHCP hands out, and forwarding to the
//     uplink zones only. Phase 1's chains hook into that zone too, so
//     "internet" or "nothing" and the notifications work there as anywhere;
//   - each covered SSID's network is the quarantine network, so the SSID's
//     password lands a device there by default;
//   - every approved MAC gets a wifi-station entry on that SSID with the
//     same password and a VLAN id whose wifi-vlan section points at the
//     SSID's own network: hostapd puts the device there instead.
//
// The VLAN id is only hostapd's label pairing a station entry with its
// wifi-vlan section; it never reaches a switch, so no VLAN of the router's
// layout is used or needed. Nothing here names an interface, bridge, VLAN
// or SSID of a particular router: everything is read at runtime.
//
// Everything this layer writes is named netgrip_quarantine*, and each
// covered SSID carries a netgrip_quarantine_network option holding its own
// network, which is how it is restored.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

const (
	qNet          = "netgrip_quarantine" // network interface, firewall zone and dhcp section
	qDevSection   = "netgrip_quarantine_dev"
	qZoneSection  = "netgrip_quarantine_zone"
	qRuleDHCP     = "netgrip_quarantine_dhcp"
	qRuleDNS      = "netgrip_quarantine_dns"
	qRuleNTP      = "netgrip_quarantine_ntp"
	qResolverPfx  = "netgrip_quarantine_resolver_"
	qUplinkPfx    = "netgrip_quarantine_uplink_"
	qWifiMarker   = "netgrip_quarantine_network" // wifi-iface option: the SSID's own network
	qVlanPfx      = "netgrip_quarantine_vlan_"
	qStaPfx       = "netgrip_quarantine_sta_"
	qVlanName     = "ngq" // suffix of hostapd's per-VLAN netdev: <ifname>.ngq
	qVlanID       = "1"
	qBridgeBase   = "br-quarantine"
	qNetmask      = "255.255.255.0"
	qKickEvery    = 10 * time.Minute
	qFDBRecentSec = 60
)

// QWifiState is the layer's intent.
type QWifiState struct {
	Enabled  bool   `json:"enabled"`
	RouterIP string `json:"router_ip,omitempty"` // the quarantine network's router address
}

// QWifiSSID describes one of the router's SSIDs for the panel.
type QWifiSSID struct {
	Section string `json:"section"`
	SSID    string `json:"ssid"`
	Network string `json:"network"` // its own network (restored when the layer goes off)
	Zone    string `json:"zone"`
	Covered bool   `json:"covered"` // in a protected zone and eligible
	Applied bool   `json:"applied"` // currently on the quarantine network
	Reason  string `json:"reason,omitempty"`
}

// QWifiProbe is the layer's state for the panel.
type QWifiProbe struct {
	Enabled     bool        `json:"enabled"`
	Subnet      string      `json:"subnet,omitempty"`
	SSIDs       []QWifiSSID `json:"ssids"`
	Quarantined int         `json:"quarantined"` // devices seen on the quarantine network lately
	Issues      []string    `json:"issues"`
}

// qWifiView is one read of the configs the layer works on.
type qWifiView struct {
	wireless map[string]uciSection
	network  map[string]uciSection
	dhcp     map[string]uciSection
	firewall map[string]uciSection
}

func readQWifiView() (qWifiView, error) {
	v := qWifiView{}
	for _, c := range []struct {
		pkg string
		dst *map[string]uciSection
	}{{"wireless", &v.wireless}, {"network", &v.network}, {"dhcp", &v.dhcp}, {"firewall", &v.firewall}} {
		show, err := uciShowFn(c.pkg)
		if err != nil {
			return v, fmt.Errorf("reading the %s config: %w", c.pkg, err)
		}
		*c.dst = parseUCIShow(show, c.pkg)
	}
	return v, nil
}

func sortedSections(m map[string]uciSection, typ string) []string {
	out := []string{}
	for name, s := range m {
		if s.Type == typ {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// qPSKEncryptions are the encryptions a per-MAC station entry works with:
// a shared password, WPA2 and/or WPA3 (tested on both, E2).
func qPSKEncryption(enc string) bool {
	base, _, _ := strings.Cut(enc, "+")
	switch base {
	case "psk", "psk2", "psk-mixed", "sae", "sae-mixed":
		return true
	}
	return false
}

// qOwnNetwork is the SSID's own network: the marker while the layer has
// it, the configured network otherwise.
func qOwnNetwork(s uciSection) []string {
	if m := s.Option(qWifiMarker); m != "" {
		return []string{m}
	}
	return s.Options["network"]
}

// qForeignStations reports wifi-station / wifi-vlan sections the layer
// does not own that apply to an iface (no iface list = every iface).
func qForeignStations(wireless map[string]uciSection, iface string) bool {
	for name, s := range wireless {
		if s.Type != "wifi-station" && s.Type != "wifi-vlan" {
			continue
		}
		if strings.HasPrefix(name, qVlanPfx) || strings.HasPrefix(name, qStaPfx) {
			continue
		}
		ifaces := s.Options["iface"]
		if len(ifaces) == 0 {
			return true
		}
		for _, i := range ifaces {
			if i == iface {
				return true
			}
		}
	}
	return false
}

// qWifiSSIDs lists the router's SSIDs and which of them the layer covers:
// those whose own network is in a protected zone and that can take
// per-MAC entries. Pure, for tests.
func qWifiSSIDs(v qWifiView, zones []QZone, protected []string) []QWifiSSID {
	prot := map[string]bool{}
	for _, z := range protected {
		prot[z] = true
	}
	zoneOf := map[string]string{}
	for _, z := range zones {
		for _, n := range z.Networks {
			zoneOf[n] = z.Name
		}
	}
	out := []QWifiSSID{}
	for _, name := range sortedSections(v.wireless, "wifi-iface") {
		s := v.wireless[name]
		own := qOwnNetwork(s)
		q := QWifiSSID{Section: name, SSID: s.Option("ssid")}
		if len(own) == 1 {
			q.Network = own[0]
			q.Zone = zoneOf[own[0]]
		}
		q.Applied = s.Option(qWifiMarker) != "" && s.Option("network") == qNet
		mode := s.Option("mode")
		switch {
		case q.Zone == "" || !prot[q.Zone]:
			q.Reason = "its network is not in a protected zone"
		case len(own) != 1:
			q.Reason = "it is attached to more than one network"
		case mode != "" && mode != "ap":
			q.Reason = "it is not an access point (mode " + mode + ")"
		case s.Option("disabled") == "1":
			q.Reason = "it is turned off"
		case !qPSKEncryption(s.Option("encryption")):
			q.Reason = "it does not use a shared password (WPA2 or WPA3 Personal)"
		case s.Option("key") == "":
			q.Reason = "its password is not stored in the config"
		case s.Option("wds") == "1":
			q.Reason = "it is a WDS link"
		case s.Option("wpa_psk_file") != "" || s.Option("sae_password_file") != "":
			q.Reason = "it already uses its own password file"
		case s.Option(qWifiMarker) == "" && s.Option("dynamic_vlan") != "" && s.Option("dynamic_vlan") != "0":
			q.Reason = "it already uses dynamic VLANs"
		case qForeignStations(v.wireless, name):
			q.Reason = "it already has per-device entries of its own"
		default:
			q.Covered = true
		}
		out = append(out, q)
	}
	return out
}

// qTakenSubnets lists every IPv4 network configured or routed on the
// router, so the quarantine subnet collides with none.
func qTakenSubnets(v qWifiView, ifaces []ubus.InterfaceState, routes []string) []*net.IPNet {
	var out []*net.IPNet
	add := func(cidr string) {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.IP.To4() != nil {
			out = append(out, n)
		}
	}
	for name, s := range v.network {
		if s.Type != "interface" || name == qNet {
			continue
		}
		for _, a := range s.Options["ipaddr"] {
			if strings.Contains(a, "/") {
				add(a)
			} else if c := subnetCIDR(a, firstNonEmpty(s.Option("netmask"), "255.255.255.0")); c != "" {
				add(c)
			}
		}
	}
	for _, i := range ifaces {
		if i.Name == qNet {
			continue
		}
		for _, a := range i.IPv4 {
			add(a)
		}
	}
	for _, r := range routes {
		add(r)
	}
	return out
}

// qPickRouterIP picks the quarantine network's router address: the first
// host of the first free /24 among a few private ranges, scanned from the
// top of 192.168.0.0/16 down (home networks crowd the bottom), then
// 172.16.0.0/12 and 10.0.0.0/8. Pure, for tests.
func qPickRouterIP(taken []*net.IPNet) (string, error) {
	overlaps := func(n *net.IPNet) bool {
		for _, t := range taken {
			if t.Contains(n.IP) || n.Contains(t.IP) {
				return true
			}
		}
		return false
	}
	try := func(a, b, c byte) (string, bool) {
		n := &net.IPNet{IP: net.IPv4(a, b, c, 0).To4(), Mask: net.CIDRMask(24, 32)}
		if overlaps(n) {
			return "", false
		}
		return net.IPv4(a, b, c, 1).String(), true
	}
	for c := 254; c >= 100; c-- {
		if ip, ok := try(192, 168, byte(c)); ok {
			return ip, nil
		}
	}
	for b := 31; b >= 16; b-- {
		if ip, ok := try(172, byte(b), 254); ok {
			return ip, nil
		}
	}
	for b := 254; b >= 200; b-- {
		if ip, ok := try(10, byte(b), 254); ok {
			return ip, nil
		}
	}
	return "", errors.New("no free private /24 found for the quarantine network")
}

// qBridgeName is the quarantine bridge's device name: the base name unless
// something else already uses it. Pure, for tests.
func qBridgeName(v qWifiView, existing []string) string {
	ours := ""
	if s, ok := v.network[qDevSection]; ok {
		ours = s.Option("name")
	}
	if ours != "" {
		return ours
	}
	used := map[string]bool{}
	for _, e := range existing {
		used[e] = true
	}
	for name, s := range v.network {
		if name != qDevSection {
			if n := s.Option("name"); n != "" {
				used[n] = true
			}
			for _, d := range s.Options["device"] {
				used[d] = true
			}
		}
	}
	for i := 0; i < 10; i++ {
		n := qBridgeBase
		if i > 0 {
			n = fmt.Sprintf("%s%d", qBridgeBase, i)
		}
		if !used[n] {
			return n
		}
	}
	return qBridgeBase
}

// qDNSFor is the DNS server list (DHCP option 6) of a network's dhcp
// section, as "6,a,b" values. Pure, for tests.
func qDNSFor(dhcp map[string]uciSection, network string) []string {
	for _, name := range sortedSections(dhcp, "dhcp") {
		s := dhcp[name]
		if s.Option("interface") != network {
			continue
		}
		var out []string
		for _, o := range s.Options["dhcp_option"] {
			if strings.HasPrefix(o, "6,") || strings.HasPrefix(o, "option:dns-server,") {
				out = append(out, o)
			}
		}
		return out
	}
	return nil
}

// qResolverIPs are the IPv4 resolvers in DHCP option values.
func qResolverIPs(opts []string) []string {
	var out []string
	for _, o := range opts {
		_, list, _ := strings.Cut(o, ",")
		for _, ip := range strings.Split(list, ",") {
			if p := net.ParseIP(strings.TrimSpace(ip)); p != nil && p.To4() != nil {
				out = append(out, p.String())
			}
		}
	}
	return out
}

// qWifiPlan is what the layer should look like.
type qWifiPlan struct {
	enabled  bool
	routerIP string
	bridge   string
	ssids    []QWifiSSID // covered ones get the layer
	approved []string
	uplinks  []string // uplink zone names
	dns      []string // dhcp_option values for the quarantine network
}

type qOps struct {
	network, dhcp, firewall, wireless []executor.Op
	radios                            map[string]bool // radios whose SSIDs change shape (restart)
	stationRadios                     map[string]bool // radios whose station entries change (data reload)
	moved                             map[string][]string
}

func (o *qOps) any() bool {
	return len(o.network)+len(o.dhcp)+len(o.firewall)+len(o.wireless) > 0
}

// ensure* append the ops that bring one section to the wanted shape.
func ensureSection(ops *[]executor.Op, cur map[string]uciSection, pkg, name, typ string, opts map[string][]string) {
	s, ok := cur[name]
	if ok && s.Type != typ {
		*ops = append(*ops, executor.Op{Kind: "uci_delete", Args: []string{pkg + "." + name}})
		ok = false
	}
	if !ok {
		*ops = append(*ops, executor.Op{Kind: "uci_set", Args: []string{pkg + "." + name, typ}})
		s = uciSection{Options: map[string][]string{}}
	}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ensureOption(ops, s, pkg+"."+name, k, opts[k])
	}
}

// ensureOption sets a scalar (one value) or rewrites a list (several, or a
// key in qListOptions) when it differs.
func ensureOption(ops *[]executor.Op, s uciSection, key, opt string, want []string) {
	have := s.Options[opt]
	if strings.Join(have, "\x00") == strings.Join(want, "\x00") {
		return
	}
	if len(want) == 1 && !qListOptions[opt] {
		*ops = append(*ops, executor.Op{Kind: "uci_set", Args: []string{key + "." + opt, want[0]}})
		return
	}
	if len(have) > 0 {
		*ops = append(*ops, executor.Op{Kind: "uci_delete", Args: []string{key + "." + opt}})
	}
	for _, w := range want {
		*ops = append(*ops, executor.Op{Kind: "uci_add_list", Args: []string{key + "." + opt, w}})
	}
}

// qListOptions are written as UCI lists; everything else as a plain
// option, the way E2 wrote network on an SSID and on its wifi-vlan, and the
// way netifd wants an interface's proto.
var qListOptions = map[string]bool{"mac": true, "iface": true, "dhcp_option": true}

func deleteSections(ops *[]executor.Op, cur map[string]uciSection, pkg string, match func(name string) bool) {
	names := []string{}
	for name := range cur {
		if match(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		*ops = append(*ops, executor.Op{Kind: "uci_delete", Args: []string{pkg + "." + n}})
	}
}

// qWifiOpsFor computes the UCI changes from the current configs to the
// plan. With the plan off, every trace is removed and every SSID gets its
// own network back. Pure, for tests.
func qWifiOpsFor(v qWifiView, p qWifiPlan) qOps {
	o := qOps{radios: map[string]bool{}, stationRadios: map[string]bool{}, moved: map[string][]string{}}
	covered := map[string]QWifiSSID{}
	if p.enabled {
		for _, s := range p.ssids {
			if s.Covered {
				covered[s.Section] = s
			}
		}
	}

	// SSIDs: restore those the layer should not hold, convert the others.
	for _, name := range sortedSections(v.wireless, "wifi-iface") {
		s := v.wireless[name]
		key := "wireless." + name
		marker := s.Option(qWifiMarker)
		if c, ok := covered[name]; ok {
			before := len(o.wireless)
			ensureOption(&o.wireless, s, key, "network", []string{qNet})
			ensureOption(&o.wireless, s, key, "dynamic_vlan", []string{"1"})
			ensureOption(&o.wireless, s, key, qWifiMarker, []string{c.Network})
			if len(o.wireless) > before {
				o.radios[s.Option("device")] = true
			}
			continue
		}
		if marker != "" {
			// Its own network back, unless someone moved it elsewhere in
			// the meantime: then only the layer's marks go.
			if strings.Join(s.Options["network"], " ") == qNet {
				o.wireless = append(o.wireless, executor.Op{Kind: "uci_set", Args: []string{key + ".network", marker}})
			}
			o.wireless = append(o.wireless, executor.Op{Kind: "uci_delete", Args: []string{key + "." + qWifiMarker}})
			if s.Option("dynamic_vlan") != "" {
				o.wireless = append(o.wireless, executor.Op{Kind: "uci_delete", Args: []string{key + ".dynamic_vlan"}})
			}
			o.radios[s.Option("device")] = true
		}
	}

	// Per covered SSID: its VLAN section and its station entries.
	wantVlan, wantSta := map[string]bool{}, map[string]bool{}
	for _, name := range sortedSections(v.wireless, "wifi-iface") {
		c, ok := covered[name]
		if !ok {
			continue
		}
		s := v.wireless[name]
		radio := s.Option("device")
		vlan, sta := qVlanPfx+name, qStaPfx+name
		wantVlan[vlan], wantSta[sta] = true, true
		before := len(o.wireless)
		ensureSection(&o.wireless, v.wireless, "wireless", vlan, "wifi-vlan", map[string][]string{
			"name": {qVlanName}, "vid": {qVlanID}, "network": {c.Network}, "iface": {name},
		})
		if len(o.wireless) > before {
			o.radios[radio] = true
		}
		if len(p.approved) == 0 {
			if _, ok := v.wireless[sta]; ok {
				o.wireless = append(o.wireless, executor.Op{Kind: "uci_delete", Args: []string{"wireless." + sta}})
				o.stationRadios[radio] = true
			}
			continue
		}
		before = len(o.wireless)
		ensureSection(&o.wireless, v.wireless, "wireless", sta, "wifi-station", map[string][]string{
			"key": {s.Option("key")}, "vid": {qVlanID}, "mac": p.approved, "iface": {name},
		})
		if len(o.wireless) > before {
			o.stationRadios[radio] = true
			o.moved[name] = qMACDiff(v.wireless[sta].Options["mac"], p.approved)
		}
	}
	deleteSections(&o.wireless, v.wireless, "wireless", func(n string) bool {
		return (strings.HasPrefix(n, qVlanPfx) && !wantVlan[n]) || (strings.HasPrefix(n, qStaPfx) && !wantSta[n])
	})
	for n := range v.wireless {
		if (strings.HasPrefix(n, qVlanPfx) && !wantVlan[n]) || (strings.HasPrefix(n, qStaPfx) && !wantSta[n]) {
			o.radios[v.wireless[strings.TrimPrefix(strings.TrimPrefix(n, qVlanPfx), qStaPfx)].Option("device")] = true
		}
	}

	if !p.enabled {
		deleteSections(&o.network, v.network, "network", func(n string) bool { return n == qNet || n == qDevSection })
		deleteSections(&o.dhcp, v.dhcp, "dhcp", func(n string) bool { return n == qNet })
		deleteSections(&o.firewall, v.firewall, "firewall", func(n string) bool {
			return n == qZoneSection || n == qRuleDHCP || n == qRuleDNS || n == qRuleNTP ||
				strings.HasPrefix(n, qResolverPfx) || strings.HasPrefix(n, qUplinkPfx)
		})
		delete(o.radios, "")
		delete(o.stationRadios, "")
		return o
	}

	// The quarantine network.
	ensureSection(&o.network, v.network, "network", qDevSection, "device", map[string][]string{
		"type": {"bridge"}, "name": {p.bridge}, "bridge_empty": {"1"},
	})
	ensureSection(&o.network, v.network, "network", qNet, "interface", map[string][]string{
		"device": {p.bridge}, "proto": {"static"}, "ipaddr": {p.routerIP}, "netmask": {qNetmask},
	})
	dhcpOpts := map[string][]string{
		"interface": {qNet}, "start": {"100"}, "limit": {"150"}, "leasetime": {"1h"},
	}
	if len(p.dns) > 0 {
		dhcpOpts["dhcp_option"] = p.dns
	}
	ensureSection(&o.dhcp, v.dhcp, "dhcp", qNet, "dhcp", dhcpOpts)
	if len(p.dns) == 0 {
		if s, ok := v.dhcp[qNet]; ok && len(s.Options["dhcp_option"]) > 0 {
			o.dhcp = append(o.dhcp, executor.Op{Kind: "uci_delete", Args: []string{"dhcp." + qNet + ".dhcp_option"}})
		}
	}

	// Its zone: fail closed. Without phase 1's chains it still reaches
	// nothing but the router's DHCP/DNS/time, the resolvers and the
	// uplinks; with them, the mode decides.
	ensureSection(&o.firewall, v.firewall, "firewall", qZoneSection, "zone", map[string][]string{
		"name": {qNet}, "network": {qNet}, "input": {"REJECT"}, "output": {"ACCEPT"}, "forward": {"REJECT"},
	})
	ensureSection(&o.firewall, v.firewall, "firewall", qRuleDHCP, "rule", map[string][]string{
		"name": {"netgrip quarantine: DHCP from the router"}, "src": {qNet}, "proto": {"udp"},
		"dest_port": {"67"}, "family": {"ipv4"}, "target": {"ACCEPT"},
	})
	ensureSection(&o.firewall, v.firewall, "firewall", qRuleDNS, "rule", map[string][]string{
		"name": {"netgrip quarantine: DNS from the router"}, "src": {qNet}, "proto": {"tcp udp"},
		"dest_port": {"53"}, "target": {"ACCEPT"},
	})
	ensureSection(&o.firewall, v.firewall, "firewall", qRuleNTP, "rule", map[string][]string{
		"name": {"netgrip quarantine: time from the router"}, "src": {qNet}, "proto": {"udp"},
		"dest_port": {"123"}, "target": {"ACCEPT"},
	})
	resolvers := qResolverIPs(p.dns)
	for i, ip := range resolvers {
		ensureSection(&o.firewall, v.firewall, "firewall", fmt.Sprintf("%s%d", qResolverPfx, i), "rule", map[string][]string{
			"name": {"netgrip quarantine: DNS to " + ip}, "src": {qNet}, "dest": {"*"}, "dest_ip": {ip},
			"proto": {"tcp udp"}, "dest_port": {"53"}, "target": {"ACCEPT"},
		})
	}
	deleteSections(&o.firewall, v.firewall, "firewall", func(n string) bool {
		var i int
		_, err := fmt.Sscanf(strings.TrimPrefix(n, qResolverPfx), "%d", &i)
		return strings.HasPrefix(n, qResolverPfx) && (err != nil || i >= len(resolvers))
	})
	for i, z := range p.uplinks {
		ensureSection(&o.firewall, v.firewall, "firewall", fmt.Sprintf("%s%d", qUplinkPfx, i), "forwarding", map[string][]string{
			"src": {qNet}, "dest": {z},
		})
	}
	deleteSections(&o.firewall, v.firewall, "firewall", func(n string) bool {
		var i int
		_, err := fmt.Sscanf(strings.TrimPrefix(n, qUplinkPfx), "%d", &i)
		return strings.HasPrefix(n, qUplinkPfx) && (err != nil || i >= len(p.uplinks))
	})
	delete(o.radios, "")
	delete(o.stationRadios, "")
	return o
}

// qMACDiff lists the MACs in one list and not the other, both ways.
func qMACDiff(a, b []string) []string {
	in := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			m[strings.ToLower(x)] = true
		}
		return m
	}
	ma, mb := in(a), in(b)
	var out []string
	for m := range ma {
		if !mb[m] {
			out = append(out, m)
		}
	}
	for m := range mb {
		if !ma[m] {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// qUplinkZones are the zone names traffic to the internet leaves through.
func qUplinkZones(zones []QZone) []string {
	out := []string{}
	for _, z := range zones {
		if z.Wan {
			out = append(out, z.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ---- Router access (seams) ----

var qRoutesFn = func() []string {
	out, err := exec.Command("ip", "-4", "route", "show", "table", "all").Output()
	if err != nil {
		return nil
	}
	var r []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.Contains(f[0], "/") {
			r = append(r, f[0])
		}
	}
	return r
}

var qNetdevsFn = func() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

var applyQWifiOps = func(ops []executor.Op) error { return executor.Apply(ops, nil) }

// qBSSFn maps wifi-iface sections to their running interface and clients.
var qBSSFn = func() map[string]ubus.WirelessInterface {
	out := map[string]ubus.WirelessInterface{}
	radios, err := ubusRadios()
	if err != nil {
		return out
	}
	for _, r := range radios {
		for _, i := range r.Interfaces {
			if i.RFaceName != "" {
				out[i.RFaceName] = i
			}
		}
	}
	return out
}

// qKickFn disconnects one station so it reconnects (and gets its VLAN).
var qKickFn = func(ifname, mac string) error {
	arg := fmt.Sprintf(`{"addr":"%s","reason":5,"deauth":true,"ban_time":0}`, mac)
	if out, err := exec.Command("ubus", "call", "hostapd."+ifname, "del_client", arg).CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// qQuarantineFDBFn lists the MACs the quarantine bridge heard from within
// the last qFDBRecentSec seconds, from the kernel's forwarding table.
var qQuarantineFDBFn = func(bridge string) map[string]bool {
	raw, err := os.ReadFile("/sys/class/net/" + bridge + "/brforward")
	if err != nil {
		return map[string]bool{}
	}
	return parseBrForward(raw, qFDBRecentSec)
}

// parseBrForward decodes /sys/class/net/<br>/brforward: 16-byte entries
// (MAC, port, is_local, age in centiseconds, ...). Local entries (the
// bridge's own addresses) and stale ones are left out. Pure, for tests.
func parseBrForward(raw []byte, maxAgeSec int) map[string]bool {
	out := map[string]bool{}
	for off := 0; off+16 <= len(raw); off += 16 {
		e := raw[off : off+16]
		if e[7] != 0 {
			continue
		}
		age := binary.NativeEndian.Uint32(e[8:12])
		if int(age/100) > maxAgeSec {
			continue
		}
		out[net.HardwareAddr(e[0:6]).String()] = true
	}
	return out
}

// ---- Applying ----

// qWifiPlanLocked builds the plan from the state and one read of the router.
func qWifiPlanLocked(st *qState, r qRouter, v qWifiView) (qWifiPlan, error) {
	p := qWifiPlan{enabled: st.Enabled && st.Wifi.Enabled}
	if !p.enabled {
		return p, nil
	}
	p.ssids = qWifiSSIDs(v, r.zones, st.Zones)
	p.approved = st.approvedMACs()
	p.uplinks = qUplinkZones(r.zones)
	p.bridge = qBridgeName(v, qNetdevsFn())
	p.routerIP = st.Wifi.RouterIP
	if s, ok := v.network[qNet]; ok && s.Option("ipaddr") != "" {
		p.routerIP = s.Option("ipaddr")
	}
	if p.routerIP == "" {
		ifaces, _ := dumpInterfacesFn()
		ip, err := qPickRouterIP(qTakenSubnets(v, ifaces, qRoutesFn()))
		if err != nil {
			return p, err
		}
		p.routerIP = ip
	}
	for _, s := range p.ssids {
		if s.Covered {
			p.dns = qDNSFor(v.dhcp, s.Network)
			break
		}
	}
	return p, nil
}

// qWifiApplyLocked brings the router to the plan: commits what changed and
// reloads only what must (a station-only change reloads hostapd's data
// files without restarting the SSID), then disconnects the stations whose
// entry changed so they reconnect on the right network.
func qWifiApplyLocked(v qWifiView, p qWifiPlan) error {
	o := qWifiOpsFor(v, p)
	if !o.any() {
		return nil
	}
	var ops []executor.Op
	ops = append(ops, o.network...)
	ops = append(ops, o.dhcp...)
	ops = append(ops, o.firewall...)
	ops = append(ops, o.wireless...)
	for _, c := range []struct {
		pkg string
		n   int
	}{{"network", len(o.network)}, {"dhcp", len(o.dhcp)}, {"firewall", len(o.firewall)}, {"wireless", len(o.wireless)}} {
		if c.n > 0 {
			ops = append(ops, executor.Op{Kind: "uci_commit", Args: []string{c.pkg}})
		}
	}
	if len(o.network) > 0 {
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"network", "reload"}})
	}
	if len(o.dhcp) > 0 {
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"dnsmasq", "reload"}})
	}
	if len(o.firewall) > 0 {
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}})
	}
	radios := map[string]bool{}
	for r := range o.radios {
		radios[r] = true
	}
	for r := range o.stationRadios {
		radios[r] = true
	}
	names := make([]string, 0, len(radios))
	for r := range radios {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		ops = append(ops, executor.Op{Kind: "wifi_reload", Args: []string{r}})
	}
	if err := applyQWifiOps(ops); err != nil {
		return err
	}
	// A restarted SSID reconnects everyone anyway; elsewhere only the
	// stations whose entry changed must reconnect.
	if len(o.moved) > 0 {
		bss := qBSSFn()
		for section, macs := range o.moved {
			if o.radios[v.wireless[section].Option("device")] {
				continue
			}
			b, ok := bss[section]
			if !ok || b.Ifname == "" {
				continue
			}
			connected := map[string]bool{}
			for _, c := range b.Clients {
				connected[strings.ToLower(c.MAC)] = true
			}
			for _, m := range macs {
				if connected[m] {
					if err := qKickFn(b.Ifname, m); err != nil {
						log.Printf("netgrip: quarantine: reconnecting %s: %v", m, err)
					}
				}
			}
		}
	}
	return nil
}

// qKicked remembers when a misplaced station was last disconnected.
var qKicked = map[string]time.Time{}

// qWifiHealLocked disconnects approved stations that sit on the quarantine
// network (a password changed before their entry followed, or hostapd did
// not apply the VLAN), at most once per qKickEvery each.
func qWifiHealLocked(st *qState, v qWifiView, p qWifiPlan, now time.Time) int {
	if !p.enabled {
		return 0
	}
	onQ := qQuarantineFDBFn(p.bridge)
	if len(onQ) == 0 {
		return len(onQ)
	}
	bss := qBSSFn()
	for _, s := range p.ssids {
		if !s.Covered || !s.Applied {
			continue
		}
		b, ok := bss[s.Section]
		if !ok || b.Ifname == "" {
			continue
		}
		for _, c := range b.Clients {
			m := strings.ToLower(c.MAC)
			if _, approved := st.Approved[m]; !approved || !onQ[m] {
				continue
			}
			if now.Sub(qKicked[m]) < qKickEvery {
				continue
			}
			qKicked[m] = now
			log.Printf("netgrip: quarantine: %s is approved but on the quarantine network; reconnecting it", m)
			if err := qKickFn(b.Ifname, m); err != nil {
				log.Printf("netgrip: quarantine: reconnecting %s: %v", m, err)
			}
		}
	}
	for m, t := range qKicked {
		if now.Sub(t) > qKickEvery {
			delete(qKicked, m)
		}
	}
	return len(onQ)
}

// qHookZones are the zones phase 1's chains hook into: the protected ones,
// plus the quarantine network's while the Wi-Fi layer is on.
func qHookZones(st *qState) []string {
	out := append([]string(nil), st.Zones...)
	if st.Wifi.Enabled {
		out = append(out, qNet)
	}
	sort.Strings(out)
	return out
}

// qUserZones drops the quarantine network's own zone from a zone list.
func qUserZones(zones []string) []string {
	out := []string{}
	for _, z := range zones {
		if z != qNet {
			out = append(out, z)
		}
	}
	return out
}

// QuarantineWifiEnable turns the Wi-Fi layer on. It restarts the covered
// SSIDs once; the server wraps it in the confirm window (wireless,
// network, dhcp and firewall).
func QuarantineWifiEnable(requesterIP string, allowUnknown bool) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return probeQuarantineLocked(), errors.New("turn the quarantine on first")
	}
	r, err := readQRouter()
	if err != nil {
		return probeQuarantineLocked(), err
	}
	v, err := readQWifiView()
	if err != nil {
		return probeQuarantineLocked(), err
	}
	covered := 0
	for _, s := range qWifiSSIDs(v, r.zones, st.Zones) {
		if s.Covered {
			covered++
		}
	}
	if covered == 0 {
		return probeQuarantineLocked(), errors.New("no Wi-Fi network of this router is in a protected zone and able to take per-device entries")
	}
	requester, err := qKeepRequester(st, requesterIP, allowUnknown)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	prev := st.Wifi
	st.Wifi.Enabled = true
	p, err := qWifiPlanLocked(st, r, v)
	if err != nil {
		return probeQuarantineLocked(), err
	}
	st.Wifi.RouterIP = p.routerIP
	if err := writeQFiles(r.ruleSet(st)); err != nil {
		return probeQuarantineLocked(), err
	}
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	fail := func(what string, err error) (QuarantineProbe, error) {
		st.Wifi = prev
		_ = saveQState(st)
		return probeQuarantineLocked(), fmt.Errorf("%s: %w", what, err)
	}
	// The network, zone and SSIDs first, then phase 1's hooks including the
	// new zone (its chains must exist before a jump into them).
	if err := qWifiApplyLocked(v, p); err != nil {
		return fail("setting up the Wi-Fi layer failed", err)
	}
	fw, err := uciShowFn("firewall")
	if err != nil {
		return fail("reading the firewall config", err)
	}
	hook := qHookZones(st)
	if err := applyQIncludes(qIncludeOps(qIncludeSections(fw), hook)); err != nil {
		return fail("hooking the quarantine network into the firewall failed", err)
	}
	if err := qVerifyLive(hook, requester); err != nil {
		return fail("the quarantine network did not come up as expected", err)
	}
	log.Printf("netgrip: quarantine Wi-Fi layer on (%d SSID(s), network %s)", covered, p.routerIP)
	return probeQuarantineLocked(), nil
}

// qWifiTeardownLocked gives every SSID its own network back and removes
// the quarantine network. Cannot lock anyone out: it only widens access.
func qWifiTeardownLocked(st *qState) error {
	v, err := readQWifiView()
	if err != nil {
		return err
	}
	if err := qWifiApplyLocked(v, qWifiPlan{}); err != nil {
		return err
	}
	st.Wifi.Enabled = false
	return nil
}

// QuarantineWifiDisable turns the Wi-Fi layer off.
func QuarantineWifiDisable() (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if err := qWifiTeardownLocked(st); err != nil {
		return probeQuarantineLocked(), fmt.Errorf("turning the Wi-Fi layer off failed: %w", err)
	}
	if st.Enabled {
		fw, err := uciShowFn("firewall")
		if err == nil {
			if err := applyQIncludes(qIncludeOps(qIncludeSections(fw), qHookZones(st))); err != nil {
				log.Printf("netgrip: quarantine: unhooking the quarantine network: %v", err)
			}
		}
	}
	_ = saveQState(st)
	log.Printf("netgrip: quarantine Wi-Fi layer off")
	return probeQuarantineLocked(), nil
}

// qWifiSyncLocked keeps the station entries in line with the approved
// list and the SSIDs' passwords, the uplinks and the resolvers in line
// with the router, and heals misplaced stations. It never changes which
// SSIDs are covered (that is the user's: enable, disable, zones).
func qWifiSyncLocked(st *qState, r qRouter, now time.Time) (QWifiProbe, error) {
	wp := QWifiProbe{Enabled: st.Wifi.Enabled, SSIDs: []QWifiSSID{}, Issues: []string{}}
	v, err := readQWifiView()
	if err != nil {
		return wp, err
	}
	p, err := qWifiPlanLocked(st, r, v)
	if err != nil {
		return wp, err
	}
	wp.SSIDs = qWifiSSIDs(v, r.zones, st.Zones)
	if !p.enabled {
		return wp, nil
	}
	wp.Subnet = p.routerIP + "/24"
	// Only SSIDs the layer already holds: a newly covered SSID waits for
	// the user (a zone change or turning the layer on again).
	held := []QWifiSSID{}
	for _, s := range p.ssids {
		if s.Applied && s.Covered {
			held = append(held, s)
		} else if s.Applied {
			// Gets its own network back in this pass.
			log.Printf("netgrip: quarantine: SSID %q leaves the Wi-Fi layer: %s", s.SSID, s.Reason)
		}
	}
	p.ssids = held
	if err := qWifiApplyLocked(v, p); err != nil {
		return wp, err
	}
	wp.Quarantined = qWifiHealLocked(st, v, p, now)
	return wp, nil
}

// qWifiFollowZonesLocked brings the layer in line with the protected
// zones: SSIDs of newly protected zones join it, the others leave.
func qWifiFollowZonesLocked(st *qState) error {
	r, err := readQRouter()
	if err != nil {
		return err
	}
	v, err := readQWifiView()
	if err != nil {
		return err
	}
	p, err := qWifiPlanLocked(st, r, v)
	if err != nil {
		return err
	}
	return qWifiApplyLocked(v, p)
}

// qWifiProbeLocked describes the layer without changing anything.
func qWifiProbeLocked(st *qState, r qRouter) QWifiProbe {
	wp := QWifiProbe{Enabled: st.Wifi.Enabled, SSIDs: []QWifiSSID{}, Issues: []string{}}
	v, err := readQWifiView()
	if err != nil {
		wp.Issues = append(wp.Issues, err.Error())
		return wp
	}
	wp.SSIDs = qWifiSSIDs(v, r.zones, st.Zones)
	if s, ok := v.network[qNet]; ok {
		if ip := s.Option("ipaddr"); ip != "" {
			wp.Subnet = ip + "/24"
		}
	}
	if !st.Wifi.Enabled {
		return wp
	}
	if s, ok := v.network[qDevSection]; ok {
		wp.Quarantined = len(qQuarantineFDBFn(s.Option("name")))
	}
	for _, s := range wp.SSIDs {
		switch {
		case s.Covered && !s.Applied:
			wp.Issues = append(wp.Issues, fmt.Sprintf("SSID %q is in a protected zone but not in the Wi-Fi layer yet: turn the layer off and on again to add it", s.SSID))
		case v.wireless[s.Section].Option(qWifiMarker) != "" && !s.Applied:
			wp.Issues = append(wp.Issues, fmt.Sprintf("SSID %q was moved off the quarantine network by hand", s.SSID))
		}
	}
	return wp
}
