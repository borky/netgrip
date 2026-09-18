package ubus

import (
	"encoding/json"
	"math"
)

// WanStatus is the state of the currently active WAN uplink. Present is
// false only when no WAN-shaped interface exists at all (pure access
// points).
type WanStatus struct {
	Present bool     `json:"present"`
	Up      bool     `json:"up"`
	Uptime  int64    `json:"uptime"`
	IPv4    []string `json:"ipv4"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns"`
}

type interfaceDump struct {
	Interface []interfaceStatus `json:"interface"`
}

type interfaceStatus struct {
	Interface string `json:"interface"`
	Up        bool   `json:"up"`
	Available bool   `json:"available"`
	Autostart bool   `json:"autostart"`
	Uptime    int64  `json:"uptime"`
	// Device is the physical device (a switch port, or null on a modem);
	// L3Device is what carries the traffic (pppoe-*, wwan0). They differ on
	// exactly the uplinks this matters for.
	Device   string `json:"device"`
	L3Device string `json:"l3_device"`
	Proto    string `json:"proto"`
	// Metric orders several default routes: the lowest one is the route the
	// kernel actually uses.
	Metric int `json:"metric"`
	// Dynamic marks an interface netifd created itself (the DHCP child of a
	// QMI uplink, the DHCPv6 side of a PPPoE one). It has no UCI section, so
	// nothing may be configured on it; its address and route belong to its
	// parent, which shares its L3Device.
	Dynamic bool `json:"dynamic"`
	IPv4    []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv4-address"`
	Route []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
		Metric  int    `json:"metric"`
	} `json:"route"`
	DNS []string `json:"dns-server"`
}

func (s interfaceStatus) hasDefaultRoute() bool {
	for _, r := range s.Route {
		if r.Target == "0.0.0.0" && r.Mask == 0 && r.Nexthop != "" {
			return true
		}
	}
	return false
}

func (s interfaceStatus) defaultGateway() string {
	for _, r := range s.Route {
		if r.Target == "0.0.0.0" && r.Mask == 0 && r.Nexthop != "" {
			return r.Nexthop
		}
	}
	return ""
}

// defaultRouteMetric is the cost of this interface's default route: the
// route's own metric when it carries one, otherwise the interface metric.
// Lower wins, and an interface without a default route is not in the running
// at all, so it reports the largest value.
func (s interfaceStatus) defaultRouteMetric() int {
	for _, r := range s.Route {
		if r.Target == "0.0.0.0" && r.Mask == 0 && r.Nexthop != "" {
			if r.Metric > 0 {
				return r.Metric
			}
			return s.Metric
		}
	}
	return math.MaxInt
}

// pickWanInterface picks the interface that best represents "the WAN".
// Multi-WAN routers name their interfaces arbitrarily (e.g. a PPPoE
// uplink named "isp" with a QMI failover still named "wan"), so this
// prefers whichever interface is actually up with a default route over
// assuming the name "wan". Falls back to an interface literally named
// "wan" when none currently qualifies, so a normal single-WAN router
// still reports "down" (rather than "absent") while its one uplink is
// disconnected. Returns ok=false when no WAN-shaped interface exists.
//
// With two uplinks connected at once there are two default routes, and the
// one the kernel uses is the one with the lowest metric — not whichever the
// dump happens to list first. Ties keep dump order, so a single-uplink
// router answers exactly as it always did.
//
// The winner is then resolved to its non-dynamic parent: on a modem uplink
// the address and the route belong to a netifd-created child that has no UCI
// section of its own, and callers use this name to read and write
// network.<name>.
func pickWanInterface(ifaces []interfaceStatus) (iface interfaceStatus, ok bool) {
	best, bestMetric, found := interfaceStatus{}, math.MaxInt, false
	for _, i := range ifaces {
		if !i.Up || !i.hasDefaultRoute() {
			continue
		}
		if m := i.defaultRouteMetric(); !found || m < bestMetric {
			best, bestMetric, found = i, m, true
		}
	}
	if found {
		return parentOf(best, ifaces), true
	}
	for _, i := range ifaces {
		if i.Interface == "wan" {
			return i, true
		}
	}
	return interfaceStatus{}, false
}

// parentOf maps a netifd-created child back to the interface that owns it,
// matched on the L3 device they share, and merges what the child knows (its
// address, route and DNS) into the parent, which has none of its own. A
// non-dynamic interface is its own parent.
func parentOf(child interfaceStatus, ifaces []interfaceStatus) interfaceStatus {
	if !child.Dynamic || child.L3Device == "" {
		return child
	}
	for _, p := range ifaces {
		if p.Dynamic || p.Interface == child.Interface || p.L3Device != child.L3Device {
			continue
		}
		merged := p
		if len(merged.IPv4) == 0 {
			merged.IPv4 = child.IPv4
		}
		if len(merged.Route) == 0 {
			merged.Route = child.Route
		}
		if len(merged.DNS) == 0 {
			merged.DNS = child.DNS
		}
		if merged.Uptime == 0 {
			merged.Uptime = child.Uptime
		}
		return merged
	}
	return child
}

func buildWanStatus(raw []byte) (*WanStatus, error) {
	var dump interfaceDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, err
	}
	iface, ok := pickWanInterface(dump.Interface)
	if !ok {
		return &WanStatus{Present: false, IPv4: []string{}, DNS: []string{}}, nil
	}
	status := &WanStatus{
		Present: true,
		Up:      iface.Up,
		Uptime:  iface.Uptime,
		IPv4:    []string{},
		Gateway: iface.defaultGateway(),
		DNS:     iface.DNS,
	}
	for _, a := range iface.IPv4 {
		status.IPv4 = append(status.IPv4, a.Address)
	}
	if status.DNS == nil {
		status.DNS = []string{}
	}
	return status, nil
}

// InterfaceState is one entry of the interface dump, flattened for callers
// that need to look at every interface rather than just "the WAN" — which is
// what deciding between several uplinks requires.
type InterfaceState struct {
	Name            string   `json:"name"`
	Proto           string   `json:"proto"`
	Device          string   `json:"device"`
	L3Device        string   `json:"l3Device"`
	Up              bool     `json:"up"`
	Available       bool     `json:"available"`
	Dynamic         bool     `json:"dynamic"`
	Metric          int      `json:"metric"`
	RouteMetric     int      `json:"routeMetric"`
	HasDefaultRoute bool     `json:"hasDefaultRoute"`
	Gateway         string   `json:"gateway,omitempty"`
	IPv4            []string `json:"ipv4"`
	DNS             []string `json:"dns"`
	Uptime          int64    `json:"uptime"`
}

// ParseInterfaceDump flattens a `network.interface dump` payload. Pure, so
// the uplink rules can be tested against real payloads without a router.
func ParseInterfaceDump(raw []byte) ([]InterfaceState, error) {
	var dump interfaceDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, err
	}
	out := make([]InterfaceState, 0, len(dump.Interface))
	for _, i := range dump.Interface {
		s := InterfaceState{
			Name:            i.Interface,
			Proto:           i.Proto,
			Device:          i.Device,
			L3Device:        i.L3Device,
			Up:              i.Up,
			Available:       i.Available,
			Dynamic:         i.Dynamic,
			Metric:          i.Metric,
			HasDefaultRoute: i.hasDefaultRoute(),
			Gateway:         i.defaultGateway(),
			IPv4:            []string{},
			DNS:             i.DNS,
			Uptime:          i.Uptime,
		}
		if s.HasDefaultRoute {
			s.RouteMetric = i.defaultRouteMetric()
		}
		for _, a := range i.IPv4 {
			s.IPv4 = append(s.IPv4, a.Address)
		}
		if s.DNS == nil {
			s.DNS = []string{}
		}
		out = append(out, s)
	}
	return out, nil
}

// DumpInterfaces lists every network interface with the fields the uplink
// rules need. Returns an empty slice when ubus is unreachable, the same way
// GetWanStatus reports "no WAN" rather than failing.
func DumpInterfaces() ([]InterfaceState, error) {
	raw, err := Call("network.interface", "dump")
	if err != nil {
		return []InterfaceState{}, err
	}
	return ParseInterfaceDump(raw)
}

func GetWanStatus() (*WanStatus, error) {
	raw, err := Call("network.interface", "dump")
	if err != nil {
		return &WanStatus{Present: false, IPv4: []string{}, DNS: []string{}}, nil
	}
	return buildWanStatus(raw)
}

// activeWANInterface runs the same dump+pick GetWanStatus uses, for callers
// that need more than the status view (config editors, port mapping).
func activeWANInterface() (interfaceStatus, bool) {
	raw, err := Call("network.interface", "dump")
	if err != nil {
		return interfaceStatus{}, false
	}
	var dump interfaceDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return interfaceStatus{}, false
	}
	return pickWanInterface(dump.Interface)
}

// ActiveWANInterfaceName returns the UCI section name (network.<name>) of
// whichever interface GetWanStatus currently reports as "the WAN" - so
// config editors read/write the same interface the status view shows,
// instead of assuming the name "wan" regardless of which uplink is actually
// active (#325: a QMI failover interface literally named "wan" next to an
// active PPPoE uplink named "isp" led the WAN settings form to show/edit
// the down failover's proto while the status card showed the active
// uplink's IP). Falls back to "wan" when nothing can be determined, so
// callers always get a usable section name.
func ActiveWANInterfaceName() string {
	if iface, ok := activeWANInterface(); ok && iface.Interface != "" {
		return iface.Interface
	}
	return "wan"
}

// ActiveWANDevice returns the raw device (e.g. "lan1", "eth1.7",
// "/dev/cdc-wdm0") backing whichever interface is currently "the WAN", or
// "" when it can't be determined. Used to find which physical switch port
// (if any) carries the internet connection, instead of assuming it's
// whichever port happens to be named "wan" (on some boards the active
// uplink is PPPoE over a port named "lan1", while the port literally named
// "wan" is a cellular failover with no Ethernet port of its own).
func ActiveWANDevice() string {
	iface, ok := activeWANInterface()
	if !ok {
		return ""
	}
	return iface.Device
}
