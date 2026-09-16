package ubus

import "encoding/json"

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
	Uptime    int64  `json:"uptime"`
	Device    string `json:"device"`
	IPv4      []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv4-address"`
	Route []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
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

// pickWanInterface picks the interface that best represents "the WAN".
// Multi-WAN routers name their interfaces arbitrarily (e.g. a PPPoE
// uplink named "isp" with a QMI failover still named "wan"), so this
// prefers whichever interface is actually up with a default route over
// assuming the name "wan". Falls back to an interface literally named
// "wan" when none currently qualifies, so a normal single-WAN router
// still reports "down" (rather than "absent") while its one uplink is
// disconnected. Returns ok=false when no WAN-shaped interface exists.
func pickWanInterface(ifaces []interfaceStatus) (iface interfaceStatus, ok bool) {
	for _, i := range ifaces {
		if i.Up && i.hasDefaultRoute() {
			return i, true
		}
	}
	for _, i := range ifaces {
		if i.Interface == "wan" {
			return i, true
		}
	}
	return interfaceStatus{}, false
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
// whichever port happens to be named "wan" (#326: on the LBR20 the active
// uplink is PPPoE over the port named "lan1"; the port literally named
// "wan" is the cellular failover, with no Ethernet port of its own).
func ActiveWANDevice() string {
	iface, ok := activeWANInterface()
	if !ok {
		return ""
	}
	return iface.Device
}
