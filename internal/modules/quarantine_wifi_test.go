package modules

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// A made-up router: two SSIDs on a protected client network, one on an
// unprotected one, one WPA2/WPA3 Enterprise, one turned off.
func qWifiTestView() qWifiView {
	w := parseUCIShow(`wireless.radio9=wifi-device
wireless.radio9.band='2g'
wireless.radio8=wifi-device
wireless.radio8.band='5g'
wireless.home2=wifi-iface
wireless.home2.device='radio9'
wireless.home2.mode='ap'
wireless.home2.ssid='Home'
wireless.home2.encryption='sae-mixed'
wireless.home2.key='dummy-pass-1'
wireless.home2.network='home'
wireless.home5=wifi-iface
wireless.home5.device='radio8'
wireless.home5.mode='ap'
wireless.home5.ssid='Home5'
wireless.home5.encryption='psk2+ccmp'
wireless.home5.key='dummy-pass-2'
wireless.home5.network='home'
wireless.guest=wifi-iface
wireless.guest.device='radio9'
wireless.guest.mode='ap'
wireless.guest.ssid='Guests'
wireless.guest.encryption='psk2'
wireless.guest.key='dummy-pass-3'
wireless.guest.network='guests'
wireless.corp=wifi-iface
wireless.corp.device='radio8'
wireless.corp.mode='ap'
wireless.corp.ssid='Corp'
wireless.corp.encryption='wpa3'
wireless.corp.network='home'
wireless.off=wifi-iface
wireless.off.device='radio8'
wireless.off.ssid='Off'
wireless.off.encryption='psk2'
wireless.off.key='dummy-pass-4'
wireless.off.network='home'
wireless.off.disabled='1'
`, "wireless")
	n := parseUCIShow(`network.home=interface
network.home.device='br-home'
network.home.proto='static'
network.home.ipaddr='192.0.2.1'
network.home.netmask='255.255.255.0'
network.guests=interface
network.guests.proto='static'
network.guests.ipaddr='198.51.100.1/24'
network.@device[0]=device
network.@device[0].name='br-home'
network.@device[0].type='bridge'
`, "network")
	d := parseUCIShow(`dhcp.home=dhcp
dhcp.home.interface='home'
dhcp.home.dhcp_option='6,192.0.2.53' '3,192.0.2.1'
dhcp.guests=dhcp
dhcp.guests.interface='guests'
`, "dhcp")
	return qWifiView{wireless: w, network: n, dhcp: d, firewall: map[string]uciSection{}}
}

var qWifiTestZones = []QZone{
	{Name: "home", Networks: []string{"home"}},
	{Name: "guests", Networks: []string{"guests"}},
	{Name: "up", Networks: []string{"uplink"}, Wan: true},
}

func TestQWifiSSIDsCoverage(t *testing.T) {
	got := map[string]QWifiSSID{}
	for _, s := range qWifiSSIDs(qWifiTestView(), qWifiTestZones, []string{"home"}) {
		got[s.Section] = s
	}
	if !got["home2"].Covered || !got["home5"].Covered {
		t.Fatalf("protected PSK/SAE SSIDs not covered: %+v", got)
	}
	for sec, why := range map[string]string{
		"guest": "not in a protected zone", "corp": "shared password", "off": "turned off",
	} {
		if got[sec].Covered || !strings.Contains(got[sec].Reason, why) {
			t.Errorf("%s: %+v, want a reason containing %q", sec, got[sec], why)
		}
	}
	// Someone else's per-device entries rule an SSID out.
	v := qWifiTestView()
	v.wireless["theirs"] = uciSection{Type: "wifi-station", Options: map[string][]string{"mac": {"02:00:00:00:00:31"}, "iface": {"home5"}}}
	for _, s := range qWifiSSIDs(v, qWifiTestZones, []string{"home"}) {
		if s.Section == "home5" && s.Covered {
			t.Fatal("an SSID with foreign station entries was covered")
		}
	}
}

func TestQPickRouterIPAvoidsEveryTakenNetwork(t *testing.T) {
	var taken []*net.IPNet
	for _, c := range []string{"192.168.254.0/24", "192.168.253.0/23", "192.168.0.0/24"} {
		_, n, _ := net.ParseCIDR(c)
		taken = append(taken, n)
	}
	ip, err := qPickRouterIP(taken)
	if err != nil || ip != "192.168.251.1" {
		t.Fatalf("picked %q, %v", ip, err)
	}
	_, all, _ := net.ParseCIDR("192.168.0.0/16")
	ip, err = qPickRouterIP([]*net.IPNet{all})
	if err != nil || !strings.HasPrefix(ip, "172.31.") {
		t.Fatalf("with 192.168/16 taken: %q, %v", ip, err)
	}
}

// qApplyOps plays UCI ops onto parsed configs, like uci would.
func qApplyOps(t *testing.T, v *qWifiView, ops []executor.Op) {
	t.Helper()
	cfg := map[string]map[string]uciSection{"wireless": v.wireless, "network": v.network, "dhcp": v.dhcp, "firewall": v.firewall}
	split := func(key string) (map[string]uciSection, string, string) {
		parts := strings.SplitN(key, ".", 3)
		m := cfg[parts[0]]
		if m == nil {
			t.Fatalf("unknown package in %q", key)
		}
		if len(parts) == 2 {
			return m, parts[1], ""
		}
		return m, parts[1], parts[2]
	}
	for _, op := range ops {
		switch op.Kind {
		case "uci_set":
			m, sec, opt := split(op.Args[0])
			if opt == "" {
				m[sec] = uciSection{Type: op.Args[1], Options: map[string][]string{}}
				continue
			}
			s, ok := m[sec]
			if !ok {
				t.Fatalf("set on missing section %q", op.Args[0])
			}
			s.Options[opt] = []string{op.Args[1]}
		case "uci_add_list":
			m, sec, opt := split(op.Args[0])
			s, ok := m[sec]
			if !ok {
				t.Fatalf("add_list on missing section %q", op.Args[0])
			}
			s.Options[opt] = append(s.Options[opt], op.Args[1])
		case "uci_del_list":
			m, sec, opt := split(op.Args[0])
			if s, ok := m[sec]; ok {
				kept := []string{}
				for _, v := range s.Options[opt] {
					if v != op.Args[1] {
						kept = append(kept, v)
					}
				}
				s.Options[opt] = kept
			}
		case "uci_delete":
			m, sec, opt := split(op.Args[0])
			if opt == "" {
				delete(m, sec)
			} else if s, ok := m[sec]; ok {
				delete(s.Options, opt)
			}
		case "uci_commit", "initd", "wifi_reload", "wifi_bounce":
		default:
			t.Fatalf("unexpected op %+v", op)
		}
	}
}

func qTestPlan(v qWifiView, approved []string) qWifiPlan {
	ssids := qWifiSSIDs(v, qWifiTestZones, []string{"home"})
	return qWifiPlan{
		enabled: true, routerIP: "192.168.254.1", bridge: "br-quarantine", ssids: ssids,
		approved: approved, uplinks: qUplinkZones(qWifiTestZones), dns: qDNSFor(v.dhcp, "home"),
	}
}

func TestQWifiOpsBuildTheLayerAndSettle(t *testing.T) {
	v := qWifiTestView()
	approved := []string{"02:00:00:00:00:0a", "02:00:00:00:00:0b"}
	o := qWifiOpsFor(v, qTestPlan(v, approved))
	if !o.radios["radio8"] || !o.radios["radio9"] {
		t.Fatalf("both radios carry a covered SSID and must reload: %v", o.radios)
	}
	var all []executor.Op
	all = append(append(append(append(all, o.network...), o.dhcp...), o.firewall...), o.wireless...)
	qApplyOps(t, &v, all)

	for _, sec := range []string{"home2", "home5"} {
		s := v.wireless[sec]
		if strings.Join(s.Options["network"], " ") != qNet || s.Option(qWifiMarker) != "home" || s.Option("dynamic_vlan") != "1" {
			t.Fatalf("%s not converted: %+v", sec, s.Options)
		}
		vl, sta := v.wireless[qVlanPfx+sec], v.wireless[qStaPfx+sec]
		if vl.Type != "wifi-vlan" || vl.Option("network") != "home" || vl.Option("vid") != sta.Option("vid") {
			t.Fatalf("%s VLAN section: %+v", sec, vl)
		}
		if sta.Type != "wifi-station" || strings.Join(sta.Options["mac"], ",") != strings.Join(approved, ",") || sta.Option("key") != v.wireless[sec].Option("key") {
			t.Fatalf("%s station section: %+v", sec, sta)
		}
		for _, m := range sta.Options["mac"] {
			if m == "00:00:00:00:00:00" {
				t.Fatal("a wildcard station entry (it overrides every other, E2)")
			}
		}
	}
	for _, sec := range []string{"home2", "home5"} {
		if v.wireless[sec].Option("okc") != "0" || v.wireless[sec].Option(qOKCMarker) != "-" {
			t.Fatalf("%s: session caching must be off while held (a resumed session keeps its old network): %+v", sec, v.wireless[sec].Options)
		}
	}
	if v.wireless["guest"].Option("network") != "guests" || v.wireless["corp"].Option(qWifiMarker) != "" {
		t.Fatal("an SSID outside the layer was touched")
	}
	if v.network[qNet].Option("ipaddr") != "192.168.254.1" || v.network[qNet].Option("device") != "br-quarantine" || v.network[qDevSection].Option("bridge_empty") != "1" {
		t.Fatalf("quarantine network: %+v %+v", v.network[qNet], v.network[qDevSection])
	}
	if strings.Join(v.dhcp[qNet].Options["dhcp_option"], " ") != "6,192.0.2.53" {
		t.Fatalf("DNS not copied from the SSID's network: %+v", v.dhcp[qNet])
	}
	z := v.firewall[qZoneSection]
	if z.Option("input") != "REJECT" || z.Option("forward") != "REJECT" || z.Option("name") != qNet {
		t.Fatalf("zone must fail closed: %+v", z)
	}
	if v.firewall[qUplinkPfx+"0"].Option("dest") != "up" || v.firewall[qResolverPfx+"0"].Option("dest_ip") != "192.0.2.53" {
		t.Fatalf("uplink forwarding / resolver rule: %+v %+v", v.firewall[qUplinkPfx+"0"], v.firewall[qResolverPfx+"0"])
	}
	if v.network[qNet].Options["proto"] == nil || len(v.network[qNet].Options["proto"]) != 1 {
		t.Fatalf("interface proto: %+v", v.network[qNet].Options["proto"])
	}
	for name, s := range v.firewall {
		if !strings.HasPrefix(name, "netgrip_quarantine") {
			t.Errorf("firewall section not named after the feature: %s", name)
		}
		if s.Type == "rule" && !strings.HasPrefix(s.Option("name"), "netgrip quarantine: ") {
			t.Errorf("rule %s not labelled: %q", name, s.Option("name"))
		}
	}
	if again := qWifiOpsFor(v, qTestPlan(v, approved)); again.any() {
		t.Fatalf("does not settle: %+v", again)
	}
}

func TestQWifiApprovingOnlyTouchesStations(t *testing.T) {
	v := qWifiTestView()
	approved := []string{"02:00:00:00:00:0a"}
	o := qWifiOpsFor(v, qTestPlan(v, approved))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))

	more := []string{"02:00:00:00:00:0a", "02:00:00:00:00:0c"}
	o = qWifiOpsFor(v, qTestPlan(v, more))
	if len(o.network)+len(o.dhcp)+len(o.firewall) > 0 || len(o.radios) > 0 {
		t.Fatalf("an approval restarted something: radios %v, ops %d/%d/%d", o.radios, len(o.network), len(o.dhcp), len(o.firewall))
	}
	if !o.stationRadios["radio8"] || !o.stationRadios["radio9"] {
		t.Fatalf("station data not reloaded: %v", o.stationRadios)
	}
	for _, sec := range []string{"home2", "home5"} {
		if strings.Join(o.moved[sec], ",") != "02:00:00:00:00:0c" {
			t.Fatalf("%s: moved %v, want only the new device", sec, o.moved[sec])
		}
	}
	// A password change follows into the entries, again without a restart.
	qApplyOps(t, &v, o.wireless)
	v.wireless["home2"].Options["key"] = []string{"dummy-pass-new"}
	o = qWifiOpsFor(v, qTestPlan(v, more))
	if len(o.radios) > 0 || !o.stationRadios["radio9"] {
		t.Fatalf("password change: radios %v, stations %v", o.radios, o.stationRadios)
	}
}

func TestQWifiOffRestoresEverything(t *testing.T) {
	v := qWifiTestView()
	o := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"}))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	// Someone moved Home5 elsewhere by hand meanwhile.
	v.wireless["home5"].Options["network"] = []string{"guests"}

	o = qWifiOpsFor(v, qWifiPlan{})
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if strings.Join(v.wireless["home2"].Options["network"], " ") != "home" {
		t.Fatalf("home2 not restored: %+v", v.wireless["home2"].Options)
	}
	if strings.Join(v.wireless["home5"].Options["network"], " ") != "guests" {
		t.Fatalf("a hand-made change was overwritten: %+v", v.wireless["home5"].Options)
	}
	for _, sec := range []string{"home2", "home5"} {
		if v.wireless[sec].Option(qWifiMarker) != "" || v.wireless[sec].Option("dynamic_vlan") != "" ||
			v.wireless[sec].Option(qOKCMarker) != "" || v.wireless[sec].Option("okc") != "" {
			t.Fatalf("%s keeps the layer's marks: %+v", sec, v.wireless[sec].Options)
		}
	}
	for _, m := range []map[string]uciSection{v.wireless, v.network, v.dhcp, v.firewall} {
		for name := range m {
			if strings.HasPrefix(name, "netgrip_quarantine") {
				t.Errorf("left behind: %s", name)
			}
		}
	}
	if again := qWifiOpsFor(v, qWifiPlan{}); again.any() {
		t.Fatalf("off does not settle: %+v", again)
	}
}

func TestQWifiNoApprovedDevicesNoStationSection(t *testing.T) {
	v := qWifiTestView()
	o := qWifiOpsFor(v, qTestPlan(v, nil))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	for name, s := range v.wireless {
		if s.Type == "wifi-station" {
			t.Fatalf("an empty station entry was written: %s %+v", name, s)
		}
	}
}

func TestParseBrForward(t *testing.T) {
	entry := func(mac string, local bool, ageCs uint32) []byte {
		e := make([]byte, 16)
		hw, _ := net.ParseMAC(mac)
		copy(e, hw)
		if local {
			e[7] = 1
		}
		binary.NativeEndian.PutUint32(e[8:12], ageCs)
		return e
	}
	raw := append(append(entry("02:00:00:00:00:41", false, 500), entry("02:00:00:00:00:42", true, 0)...), entry("02:00:00:00:00:43", false, 90000)...)
	got := parseBrForward(raw, 60)
	keys := []string{}
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "02:00:00:00:00:41" {
		t.Fatalf("recent remote entries: %v (local and stale ones must be left out)", keys)
	}
}

func TestQHookZonesAddsTheQuarantineZoneOnlyWithTheLayer(t *testing.T) {
	st := &qState{Zones: []string{"home"}}
	if strings.Join(qHookZones(st), ",") != "home" {
		t.Fatal("hooked the quarantine zone without the layer")
	}
	st.Wifi.Enabled = true
	if strings.Join(qHookZones(st), ",") != "home,"+qNet {
		t.Fatalf("hooks: %v", qHookZones(st))
	}
	if strings.Join(qUserZones([]string{"home", qNet}), ",") != "home" {
		t.Fatal("the quarantine zone leaked into the user's zones")
	}
	if _, err := validateZones([]string{qNet}, []QZone{{Name: qNet, Networks: []string{qNet}}}); err == nil {
		t.Fatal("the quarantine zone can be picked as a protected zone")
	}
}

// renderUCIShow prints parsed sections back the way `uci show` does.
func renderUCIShow(pkg string, m map[string]uciSection) string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		s := m[n]
		b.WriteString(pkg + "." + n + "=" + s.Type + "\n")
		opts := make([]string, 0, len(s.Options))
		for o := range s.Options {
			opts = append(opts, o)
		}
		sort.Strings(opts)
		for _, o := range opts {
			q := make([]string, len(s.Options[o]))
			for i, v := range s.Options[o] {
				q[i] = "'" + v + "'"
			}
			b.WriteString(pkg + "." + n + "." + o + "=" + strings.Join(q, " ") + "\n")
		}
	}
	return b.String()
}

type qWifiFake struct {
	v      qWifiView
	kicked []string
	ops    [][]executor.Op
	stuck  bool // the interface stays in its old bridge (reload instead of restart)
}

// newQWifiFake extends the phase 1 fake router with Wi-Fi, network and
// DHCP configs held in memory, and an SSID "home2" on the protected
// network with two stations connected.
func newQWifiFake(t *testing.T, f *qFake) *qWifiFake {
	t.Helper()
	w := &qWifiFake{v: qWifiTestView()}
	w.v.dhcp = parseUCIShow(qTestDhcp, "dhcp")
	oShow, oApply, oBSS, oKick, oFDB, oDevs, oRoutes := uciShowFn, applyQWifiOps, qBSSFn, qKickFn, qQuarantineFDBFn, qNetdevsFn, qRoutesFn
	t.Cleanup(func() {
		uciShowFn, applyQWifiOps, qBSSFn, qKickFn, qQuarantineFDBFn, qNetdevsFn, qRoutesFn = oShow, oApply, oBSS, oKick, oFDB, oDevs, oRoutes
	})
	base := uciShowFn
	uciShowFn = func(pkg string) (string, error) {
		switch pkg {
		case "wireless":
			return renderUCIShow("wireless", w.v.wireless), nil
		case "network":
			return renderUCIShow("network", w.v.network), nil
		case "dhcp":
			return renderUCIShow("dhcp", w.v.dhcp), nil
		case "firewall":
			s, err := base(pkg)
			return s + renderUCIShow("firewall", w.v.firewall), err
		}
		return base(pkg)
	}
	applyQWifiOps = func(ops []executor.Op) error {
		w.ops = append(w.ops, ops)
		qApplyOps(t, &w.v, ops)
		return nil
	}
	qBSSFn = func() map[string]ubus.WirelessInterface {
		return map[string]ubus.WirelessInterface{"home2": {Ifname: "phy9-ap0", RFaceName: "home2", Clients: []ubus.WirelessClient{
			{MAC: "02:00:00:00:00:10"}, {MAC: "02:00:00:00:00:66"},
		}}}
	}
	qKickFn = func(ifname, mac string) error { w.kicked = append(w.kicked, ifname+" "+mac); return nil }
	qQuarantineFDBFn = func(string) map[string]bool { return map[string]bool{} }
	qNetdevsFn = func() []string { return []string{"br-home", "eth9"} }
	// The SSID's interface follows its config, as after a radio restart.
	oMaster, oAttach := qMasterFn, qAttachTimeout
	t.Cleanup(func() { qMasterFn, qAttachTimeout = oMaster, oAttach })
	qAttachTimeout = 0
	qMasterFn = func(ifname string) string {
		if w.stuck || w.v.wireless["home2"].Option("network") != qNet {
			return "br-home"
		}
		return "br-quarantine"
	}
	oRun, oSnap, oRestore := qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn
	t.Cleanup(func() { qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn = oRun, oSnap, oRestore })
	qDnsmasqRuntimeFn = func() qDnsmasqServing { return qServing(qDnsmasqHealthy) }
	qSnapshotFn = func(string) (string, error) { return "", nil }
	qRestoreFn = func(string, string) error { return nil }
	oWait, oPending, oRecheck := qDnsmasqWaitFn, qUCIPendingFn, qDHCPRecheckDelay
	qDnsmasqWaitFn = func(time.Time) {}
	qUCIPendingFn = func(string) (string, error) { return "", nil }
	qDHCPRecheckDelay = 0
	t.Cleanup(func() { qDnsmasqWaitFn, qUCIPendingFn, qDHCPRecheckDelay = oWait, oPending, oRecheck })
	qRoutesFn = func() []string { return []string{"192.0.2.0/24"} }
	return w
}

func TestQuarantineWifiLayerEndToEnd(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)

	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	st := loadQState()
	if !st.Wifi.Enabled || st.Wifi.RouterIP == "" {
		t.Fatalf("state: %+v", st.Wifi)
	}
	home2 := w.v.wireless["home2"]
	if home2.Option("network") != qNet || home2.Option(qWifiMarker) != "home" {
		t.Fatalf("SSID not on the quarantine network: %+v", home2.Options)
	}
	if got := w.v.wireless[qStaPfx+"home2"].Options["mac"]; strings.Join(got, ",") != "02:00:00:00:00:10" {
		t.Fatalf("station entries: %v (the requester must be among them)", got)
	}
	// Phase 1 hooks into the quarantine network's zone too.
	actual := qActualZones(mustShowPkg(t, "firewall"))
	if strings.Join(actual, ",") != "home,"+qNet {
		t.Fatalf("hooked zones: %v", actual)
	}
	if strings.Join(loadQState().Zones, ",") != "home" {
		t.Fatalf("the quarantine zone leaked into the protected zones: %v", loadQState().Zones)
	}
	if p := ProbeQuarantine(); !p.Wifi.Enabled || p.Wifi.Subnet == "" || qZoneMap(p.Zones)[qNet].Name != "" {
		t.Fatalf("probe: %+v", p.Wifi)
	}

	// Approving a connected device on a WPA3 SSID: its entry, and one
	// restart of its radio a little later (hostapd reads SAE entries only
	// when the BSS starts; a kick would resume the old placement).
	w.kicked = nil
	base := time.Now()
	qNowFn = func() time.Time { return base }
	if _, err := QuarantineApprove([]QApproveItem{{MAC: "02:00:00:00:00:66"}}); err != nil {
		t.Fatal(err)
	}
	if got := w.v.wireless[qStaPfx+"home2"].Options["mac"]; strings.Join(got, ",") != "02:00:00:00:00:10,02:00:00:00:00:66" {
		t.Fatalf("station entries after approve: %v", got)
	}
	if len(w.kicked) != 0 || qRestartDue["radio9"].IsZero() {
		t.Fatalf("kicked %v, restart due %v: want a scheduled restart", w.kicked, qRestartDue)
	}
	for _, op := range w.ops[len(w.ops)-1] {
		if op.Kind == "wifi_reload" && op.Args[0] == "radio9" {
			t.Fatal("a WPA3 approval reloaded the radio at once: devices drop and rejoin where they were before the restart")
		}
	}
	// Revoking it soon after joins the same restart.
	qNowFn = func() time.Time { return base.Add(5 * time.Second) }
	if _, err := QuarantineRevoke("02:00:00:00:00:66", "192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	w.ops = nil
	qPoll(base.Add(10 * time.Second)) // not due yet
	qPoll(base.Add(5*time.Second + qRestartDebounce))
	restarts := 0
	for _, batch := range w.ops {
		for _, op := range batch {
			if op.Kind == "wifi_bounce" && op.Args[0] == "radio9" {
				restarts++
			}
		}
	}
	if restarts != 1 {
		t.Fatalf("%d restarts for an approve and a revoke in a row, want one", restarts)
	}

	// The poller syncs the layer and finds it settled: nothing to write.
	w.ops = nil
	synced := 0
	qQuarantineFDBFn = func(string) map[string]bool { synced++; return map[string]bool{} }
	qPoll(time.Now().Add(time.Hour))
	if synced == 0 {
		t.Fatal("the poller did not sync the Wi-Fi layer")
	}
	if len(w.ops) != 0 {
		t.Fatalf("the poller rewrote a settled layer: %v", w.ops)
	}

	// Turning the quarantine off takes the layer with it.
	if _, err := QuarantineDisable(); err != nil {
		t.Fatal(err)
	}
	if w.v.wireless["home2"].Option("network") != "home" || w.v.wireless["home2"].Option(qWifiMarker) != "" {
		t.Fatalf("SSID not restored: %+v", w.v.wireless["home2"].Options)
	}
	for _, m := range []map[string]uciSection{w.v.wireless, w.v.network, w.v.dhcp, w.v.firewall} {
		for name := range m {
			if strings.HasPrefix(name, "netgrip_quarantine") {
				t.Errorf("left behind: %s", name)
			}
		}
	}
	if loadQState().Wifi.Enabled {
		t.Fatal("the layer is still recorded as on")
	}
}

func TestQuarantineWifiEnableNeedsACoveredSSID(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "guests")
	w := newQWifiFake(t, f)
	w.v.wireless["guest"].Options["encryption"] = []string{"wpa2"} // Enterprise: not coverable
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err == nil {
		t.Fatal("turned on with no SSID it can cover")
	}
	if loadQState().Wifi.Enabled || len(w.ops) != 0 {
		t.Fatal("something was changed")
	}
}

func mustShowPkg(t *testing.T, pkg string) string {
	t.Helper()
	s, err := uciShowFn(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQuarantineWifiHealsAMisplacedApprovedDevice(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	old := qKicked
	qKicked = map[string]time.Time{}
	t.Cleanup(func() { qKicked = old })
	// On a WPA2-only SSID a kick is enough.
	w.v.wireless["home2"].Options["encryption"] = []string{"psk2"}
	// The approved requester and an unknown device are both heard on the
	// quarantine network.
	qQuarantineFDBFn = func(string) map[string]bool {
		return map[string]bool{"02:00:00:00:00:10": true, "02:00:00:00:00:66": true}
	}
	w.kicked = nil
	now := time.Now().Add(time.Hour)
	qPoll(now)
	if strings.Join(w.kicked, ";") != "phy9-ap0 02:00:00:00:00:10" {
		t.Fatalf("kicked %v, want only the approved device", w.kicked)
	}
	qPoll(now.Add(qFullCheckEvery))
	if len(w.kicked) != 1 {
		t.Fatalf("kicked again within %v: %v", qKickEvery, w.kicked)
	}
	qPoll(now.Add(qKickEvery + qFullCheckEvery))
	if len(w.kicked) != 2 {
		t.Fatalf("not retried after %v: %v", qKickEvery, w.kicked)
	}
}

func TestParseUCIValuesDecodesEscapedQuotes(t *testing.T) {
	for in, want := range map[string]string{
		`'it'\''s'`:        "it's",
		`'a' 'b c' 'd'`:    "a|b c|d",
		`''`:               "",
		`'x'\'''\''y' 'z'`: "x''y|z",
		`'pa;ss'`:          "pa;ss",
		`unquoted`:         "unquoted",
		`'unbalanced`:      "'unbalanced",
	} {
		if got := strings.Join(parseUCIValues(in), "|"); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestQWifiSSIDsPasswordsAndNames(t *testing.T) {
	v := qWifiTestView()
	v.wireless["home2"].Options["key"] = []string{"it's fine"}
	v.wireless["home5"].Options["key"] = []string{"no;way"}
	v.wireless["@wifi-iface[3]"] = uciSection{Type: "wifi-iface", Options: map[string][]string{
		"device": {"radio9"}, "mode": {"ap"}, "ssid": {"Anon"}, "encryption": {"psk2"}, "key": {"dummy-pass-5"}, "network": {"home"},
	}}
	got := map[string]QWifiSSID{}
	for _, s := range qWifiSSIDs(v, qWifiTestZones, []string{"home"}) {
		got[s.Section] = s
	}
	if !got["home2"].Covered {
		t.Fatalf("an apostrophe in the password must be fine: %+v", got["home2"])
	}
	if got["home5"].Covered || !strings.Contains(got["home5"].Reason, "cannot write") {
		t.Fatalf("a password the executor refuses: %+v", got["home5"])
	}
	if got["@wifi-iface[3]"].Covered {
		t.Fatalf("an unnamed section was covered: %+v", got["@wifi-iface[3]"])
	}
}

func TestQWifiHeldSSIDStaysWhileTurnedOff(t *testing.T) {
	v := qWifiTestView()
	o := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"}))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	v.wireless["home2"].Options["disabled"] = []string{"1"} // a Wi-Fi schedule's night
	for _, s := range qWifiSSIDs(v, qWifiTestZones, []string{"home"}) {
		if s.Section == "home2" && (!s.Covered || !s.Applied) {
			t.Fatalf("a held SSID left the layer when turned off: %+v", s)
		}
	}
	if again := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"})); again.any() {
		t.Fatalf("turning an SSID off changed the layer: %+v", again.wireless)
	}
}

func TestQWifiLastRevokeStillReconnects(t *testing.T) {
	v := qWifiTestView()
	o := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"}))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	o = qWifiOpsFor(v, qTestPlan(v, nil))
	if strings.Join(o.moved["home2"], ",") != "02:00:00:00:00:0a" {
		t.Fatalf("the last revoked device is not reconnected: %v", o.moved)
	}
}

func TestQTakenSubnetsIgnoresDefaultAndSplitRoutes(t *testing.T) {
	taken := qTakenSubnets(qWifiView{}, nil, []string{"0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0", "198.51.100.0/24"})
	if len(taken) != 1 || taken[0].String() != "198.51.100.0/24" {
		t.Fatalf("taken: %v", taken)
	}
	if _, err := qPickRouterIP(taken); err != nil {
		t.Fatal(err)
	}
}

func TestQWifiDnsmasqInterfaceList(t *testing.T) {
	v := qWifiTestView()
	v.dhcp["main"] = uciSection{Type: "dnsmasq", Options: map[string][]string{"interface": {"home"}}}
	o := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"}))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if strings.Join(v.dhcp["main"].Options["interface"], ",") != "home,"+qNet {
		t.Fatalf("a bound dnsmasq does not serve the quarantine network: %v", v.dhcp["main"].Options["interface"])
	}
	o = qWifiOpsFor(v, qWifiPlan{})
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if strings.Join(v.dhcp["main"].Options["interface"], ",") != "home" {
		t.Fatalf("not removed again: %v", v.dhcp["main"].Options["interface"])
	}
}

func TestQuarantineWifiRevertIsRecordedNotRebuilt(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	before := qWifiView{wireless: qCopySections(w.v.wireless), network: qCopySections(w.v.network), dhcp: qCopySections(w.v.dhcp), firewall: qCopySections(w.v.firewall)}
	beforeIncludes := map[string]map[string]string{}
	for k, v := range f.sections {
		beforeIncludes[k] = v
	}
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	// The confirm window ran out: every config is put back.
	w.v = before
	f.sections = beforeIncludes
	w.ops = nil
	qPoll(time.Now().Add(time.Hour))
	if loadQState().Wifi.Enabled {
		t.Fatal("the reverted layer is still recorded as on")
	}
	if _, ok := w.v.network[qNet]; ok {
		t.Fatal("the reverted quarantine network was rebuilt")
	}
	if strings.Join(qActualZones(mustShowPkg(t, "firewall")), ",") != "home" {
		t.Fatalf("hooks after the revert: %v", qActualZones(mustShowPkg(t, "firewall")))
	}
}

func qCopySections(m map[string]uciSection) map[string]uciSection {
	out := map[string]uciSection{}
	for k, s := range m {
		opts := map[string][]string{}
		for o, v := range s.Options {
			opts[o] = append([]string(nil), v...)
		}
		out[k] = uciSection{Type: s.Type, Options: opts}
	}
	return out
}

func TestQWirelessShowWithoutWifiConfig(t *testing.T) {
	old := qWirelessConfig
	qWirelessConfig = t.TempDir() + "/wireless"
	t.Cleanup(func() { qWirelessConfig = old })
	out, err := qWirelessShowFn()
	if err != nil || out != "" {
		t.Fatalf("a router without Wi-Fi: %q, %v", out, err)
	}
}

func TestQWifiDnsmasqOnlyTheServingInstance(t *testing.T) {
	v := qWifiTestView()
	v.dhcp["main"] = uciSection{Type: "dnsmasq", Options: map[string][]string{"interface": {"home"}}}
	v.dhcp["guestdns"] = uciSection{Type: "dnsmasq", Options: map[string][]string{"interface": {"guests"}}}
	v.dhcp["home"].Options["instance"] = []string{"main"}
	p := qTestPlan(v, []string{"02:00:00:00:00:0a"})
	p.ownNetwork = "home"
	o := qWifiOpsFor(v, p)
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if strings.Join(v.dhcp["main"].Options["interface"], ",") != "home,"+qNet || strings.Join(v.dhcp["guestdns"].Options["interface"], ",") != "guests" {
		t.Fatalf("instances: main %v, guest %v", v.dhcp["main"].Options["interface"], v.dhcp["guestdns"].Options["interface"])
	}
	if v.dhcp[qNet].Option("instance") != "main" {
		t.Fatalf("the quarantine range is not tied to the serving instance: %+v", v.dhcp[qNet].Options)
	}
}

func TestQuarantineZonesLeavingNoSSIDTurnTheLayerOffWithAReason(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	p, err := QuarantineSetZones([]string{"vpn"}, "192.0.2.10", false) // no SSID there
	if err != nil {
		t.Fatal(err)
	}
	if p.Wifi.Enabled || p.Wifi.OffReason == "" {
		t.Fatalf("probe after the zone change: %+v", p.Wifi)
	}
	if w.v.wireless["home2"].Option("network") != "home" {
		t.Fatalf("SSID not restored: %+v", w.v.wireless["home2"].Options)
	}
	if strings.Join(qActualZones(mustShowPkg(t, "firewall")), ",") != "vpn" {
		t.Fatalf("hooks: %v", qActualZones(mustShowPkg(t, "firewall")))
	}
	// Turning it on again clears the reason.
	if _, err := QuarantineSetZones([]string{"home"}, "192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	if loadQState().Wifi.OffReason != "" {
		t.Fatal("the old reason survived turning the layer on")
	}
}

func TestQuarantineEnableAgainKeepsAWorkingWifiLayer(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	w.ops = nil
	f.enable(t, "internet", "home") // a repeated request
	if w.v.wireless["home2"].Option("network") != qNet {
		t.Fatal("a repeated enable tore down a working Wi-Fi layer")
	}
}

// Shaped like a real generated dnsmasq config, with dummy addresses.
const qDnsmasqHealthy = `bind-dynamic
dhcp-range=set:lan,192.0.2.100,192.0.2.249,255.255.255.0,12h
dhcp-range=set:guests,198.51.100.100,198.51.100.249,255.255.255.0,12h
`

func qServing(confs ...string) qDnsmasqServing {
	m := map[string]string{}
	for i, c := range confs {
		m[fmt.Sprintf("dnsmasq.conf.cfg%d", i)] = c
	}
	return parseDnsmasqServing(m)
}

func TestQDHCPRegression(t *testing.T) {
	before := qServing(qDnsmasqHealthy)
	own := qOwnDHCP{bridge: "br-quarantine", routerIP: "192.168.254.1"}
	withOurs := qDnsmasqHealthy + "dhcp-range=set:netgrip_quarantine,192.168.254.100,192.168.254.249,255.255.255.0,1h\n"
	for name, c := range map[string]struct {
		after string
		bad   bool
	}{
		"our range added":               {withOurs, false},
		"bound to the quarantine alone": {withOurs + "interface=br-quarantine\n", true}, // what happened on 2026-11-14
		"a range lost":                  {"dhcp-range=set:lan,192.0.2.100,192.0.2.249,255.255.255.0,12h\n", true},
		"lease time changed only":       {strings.ReplaceAll(qDnsmasqHealthy, "12h", "6h"), false},
		"a WAN coming up (exclusion)":   {qDnsmasqHealthy + "no-dhcp-interface=pppoe-wan\n", false},
		"a listen address added":        {qDnsmasqHealthy + "listen-address=192.0.2.1\n", true},
		"interface-name is not binding": {qDnsmasqHealthy + "interface-name=router.lan,lan\n", false},
	} {
		got := qDHCPRegression(before, qServing(c.after), own)
		if (got != "") != c.bad {
			t.Errorf("%s: %q", name, got)
		}
	}
	// Turning the layer off removes our own range: fine.
	if got := qDHCPRegression(qServing(withOurs), before, own); got != "" {
		t.Fatalf("our own range going away was taken for a regression: %q", got)
	}
	// A bound instance may gain ours, not lose its own.
	bound := qServing(qDnsmasqHealthy + "interface=br-home\n")
	if got := qDHCPRegression(bound, qServing(qDnsmasqHealthy+"interface=br-home\ninterface=br-quarantine\n"), own); got != "" {
		t.Fatalf("adding ours to a bound instance: %q", got)
	}
	if got := qDHCPRegression(bound, qServing(qDnsmasqHealthy+"interface=br-quarantine\n"), own); got == "" {
		t.Fatal("a bound instance losing its interface passed")
	}
	if got := qDHCPRegression(bound, qServing(qDnsmasqHealthy+"interface=br-home\ninterface=br-iot\n"), own); got != "" {
		t.Fatalf("a bound instance gaining a listed network that came up: %q", got)
	}
	// Two instances: one already bound must not hide the other becoming bound.
	two := qServing(qDnsmasqHealthy, "interface=br-guest\ndhcp-range=set:g,203.0.113.100,203.0.113.200,255.255.255.0,1h\n")
	if got := qDHCPRegression(two, qServing(qDnsmasqHealthy+"interface=br-quarantine\n", "interface=br-guest\ndhcp-range=set:g,203.0.113.100,203.0.113.200,255.255.255.0,1h\n"), own); got == "" {
		t.Fatal("an unbound instance became bound and passed because another one is bound")
	}
}

func TestParseUCIValuesEmptyListIsNoValues(t *testing.T) {
	if got := parseUCIValues(""); len(got) != 0 {
		t.Fatalf("an empty list read as %q", got)
	}
	if got := parseUCIValues("''"); len(got) != 1 || got[0] != "" {
		t.Fatalf("an empty string value read as %q", got)
	}
	// The 2026-11-14 shape: uci show prints an emptied list as `key=`.
	v := parseUCIShow("dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].interface=\n", "dhcp")
	if len(v["@dnsmasq[0]"].Options["interface"]) != 0 {
		t.Fatalf("an empty interface list: %q", v["@dnsmasq[0]"].Options["interface"])
	}
}

func TestQWifiEmptyDnsmasqListIsNotBound(t *testing.T) {
	v := qWifiTestView()
	v.dhcp["@dnsmasq[0]"] = uciSection{Type: "dnsmasq", Options: map[string][]string{"interface": {""}}}
	p := qTestPlan(v, []string{"02:00:00:00:00:0a"})
	p.ownNetwork = "home"
	for _, op := range qWifiOpsFor(v, p).dhcp {
		if strings.Contains(op.Args[0], "@dnsmasq") {
			t.Fatalf("an unbound dnsmasq was bound: %+v", op)
		}
	}
}

func TestQuarantineWifiRefusesForeignPendingChanges(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	qUCIPendingFn = func(pkg string) (string, error) {
		if pkg == "dhcp" {
			return "dhcp.cfg01411c.interface='x'", nil
		}
		return "", nil
	}
	_, err := QuarantineWifiEnable("192.0.2.10", false)
	if err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
		t.Fatalf("went ahead over someone else's pending changes: %v", err)
	}
	if len(w.ops) != 0 {
		t.Fatalf("changed something: %v", w.ops)
	}
}

func TestQuarantineWifiPollerTurnsOffOnDHCPLoss(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	// Approving makes the next sync touch the station entries only; force a
	// DHCP change by moving the resolver, and make dnsmasq lose a range.
	w.v.dhcp["home"].Options["dhcp_option"] = []string{"6,192.0.2.54"}
	calls := 0
	qDnsmasqRuntimeFn = func() qDnsmasqServing {
		calls++
		if calls == 1 {
			return qServing(qDnsmasqHealthy)
		}
		return qServing("dhcp-range=set:lan,192.0.2.100,192.0.2.249,255.255.255.0,12h\n")
	}
	qPoll(time.Now().Add(time.Hour))
	st := loadQState()
	if st.Wifi.Enabled || !strings.Contains(st.Wifi.OffReason, "DHCP") {
		t.Fatalf("after a DHCP loss in the poller: %+v", st.Wifi)
	}
	if w.v.wireless["home2"].Option("network") != "home" {
		t.Fatal("the SSID was not given its own network back")
	}
}

func TestQuarantineWifiEnableRestoresDHCPWhenItBreaks(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	oRun, oSnap, oRestore := qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn
	t.Cleanup(func() { qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn = oRun, oSnap, oRestore })
	calls := 0
	qDnsmasqRuntimeFn = func() qDnsmasqServing {
		calls++
		if calls == 1 {
			return qServing(qDnsmasqHealthy)
		}
		// Whatever the cause, dnsmasq ends up serving the quarantine alone.
		return qServing(qDnsmasqHealthy + "interface=br-quarantine\n")
	}
	qSnapshotFn = func(c string) (string, error) { return "snapshot-of-" + c, nil }
	restored := ""
	qRestoreFn = func(c, content string) error { restored = c + ":" + content; return nil }

	if _, err := QuarantineWifiEnable("192.0.2.10", false); err == nil || !strings.Contains(err.Error(), "stopped DHCP") {
		t.Fatalf("enable went ahead with DHCP broken: %v", err)
	}
	if restored != "dhcp:snapshot-of-dhcp" {
		t.Fatalf("the DHCP config was not put back: %q", restored)
	}
	last := w.ops[len(w.ops)-1]
	if len(last) != 1 || last[0].Kind != "initd" || last[0].Args[0] != "dnsmasq" {
		t.Fatalf("dnsmasq not reloaded after the restore: %+v", last)
	}
	if loadQState().Wifi.Enabled {
		t.Fatal("recorded as on")
	}
}

func TestQApplyCleanRevertsItsOwnHalfAppliedChanges(t *testing.T) {
	newQFake(t)
	oPending, oRevert := qUCIPendingFn, qUCIRevertFn
	t.Cleanup(func() { qUCIPendingFn, qUCIRevertFn = oPending, oRevert })
	qUCIPendingFn = func(pkg string) (string, error) {
		if pkg == "dhcp" {
			return "dhcp.netgrip_quarantine='dhcp'", nil
		}
		return "", nil
	}
	var reverted []string
	qUCIRevertFn = func(pkg string) error { reverted = append(reverted, pkg); return nil }
	// An op that fails (an invalid key: refused before uci runs).
	// Only ops validation refuses run here, so no real uci is touched even
	// where one is installed. A config this batch never touched is not
	// reverted, whatever is pending in it.
	err := qApplyClean([]executor.Op{
		{Kind: "uci_set", Args: []string{"dhcp.bad key", "x"}},
	})
	if err == nil {
		t.Fatal("an invalid op passed")
	}
	if len(reverted) != 0 {
		t.Fatalf("reverted %v although this batch had staged nothing", reverted)
	}
}

func TestQuarantineWifiLeftoversAreRetried(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	st := loadQState()
	st.Wifi.Enabled, st.Wifi.Leftovers, st.Wifi.OffReason = false, true, "test"
	_ = saveQState(st)
	if p := ProbeQuarantine(); len(p.Wifi.Issues) == 0 {
		t.Fatal("leftovers not reported")
	}
	qPoll(time.Now().Add(time.Hour))
	if loadQState().Wifi.Leftovers || w.v.wireless["home2"].Option("network") != "home" {
		t.Fatalf("leftovers not removed: %+v %+v", loadQState().Wifi, w.v.wireless["home2"].Options)
	}
}

func TestQuarantineWifiEnableRestartsTheRadioAndChecksTheBridge(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	bounced := false
	for _, batch := range w.ops {
		for _, op := range batch {
			if op.Kind == "wifi_reload" && len(op.Args) == 1 && op.Args[0] == "radio9" {
				t.Fatal("the SSID's move was only reloaded: its interface would stay in the old bridge")
			}
			bounced = bounced || (op.Kind == "wifi_bounce" && op.Args[0] == "radio9")
		}
	}
	if !bounced {
		t.Fatal("the radio was not restarted")
	}
}

func TestQuarantineWifiEnableFailsWhenTheSSIDStaysInItsBridge(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	w.stuck = true
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err == nil || !strings.Contains(err.Error(), "not on the quarantine network") {
		t.Fatalf("enable reported success with the SSID in its old bridge: %v", err)
	}
}

func TestQuarantineWifiPollerRepairsAStuckSSID(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	old := qBounced
	qBounced = map[string]time.Time{}
	t.Cleanup(func() { qBounced = old })
	w.stuck = true // e.g. something reloaded the radio in place
	if p := ProbeQuarantine(); len(p.Wifi.Issues) == 0 {
		t.Fatal("a stuck SSID is not reported")
	}
	w.ops = nil
	now := time.Now().Add(time.Hour)
	qPoll(now)
	qPoll(now.Add(qFullCheckEvery))
	bounces := 0
	for _, batch := range w.ops {
		for _, op := range batch {
			if op.Kind == "wifi_bounce" {
				bounces++
			}
		}
	}
	if bounces != 1 {
		t.Fatalf("%d radio restarts in two polls, want exactly one", bounces)
	}
}

func TestQWifiRestoresAnExplicitOKC(t *testing.T) {
	v := qWifiTestView()
	v.wireless["home2"].Options["okc"] = []string{"1"}
	o := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"}))
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if v.wireless["home2"].Option("okc") != "0" || v.wireless["home2"].Option(qOKCMarker) != "1" {
		t.Fatalf("held: %+v", v.wireless["home2"].Options)
	}
	if again := qWifiOpsFor(v, qTestPlan(v, []string{"02:00:00:00:00:0a"})); again.any() {
		t.Fatalf("does not settle: %+v", again.wireless)
	}
	o = qWifiOpsFor(v, qWifiPlan{})
	qApplyOps(t, &v, append(append(append(o.network, o.dhcp...), o.firewall...), o.wireless...))
	if v.wireless["home2"].Option("okc") != "1" || v.wireless["home2"].Option(qOKCMarker) != "" {
		t.Fatalf("restored: %+v", v.wireless["home2"].Options)
	}
}

func TestQuarantineWifiHealOnWPA3RestartsTheRadioOnce(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	w := newQWifiFake(t, f)
	if _, err := QuarantineWifiEnable("192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	old := qKicked
	qKicked = map[string]time.Time{}
	t.Cleanup(func() { qKicked = old })
	qQuarantineFDBFn = func(string) map[string]bool { return map[string]bool{"02:00:00:00:00:10": true} }
	w.kicked, w.ops = nil, nil
	now := time.Now().Add(time.Hour)
	qPoll(now)
	qPoll(now.Add(qRestartDebounce + time.Second))
	restarts := 0
	for _, batch := range w.ops {
		for _, op := range batch {
			if op.Kind == "wifi_bounce" {
				restarts++
			}
		}
	}
	if len(w.kicked) != 0 || restarts != 1 {
		t.Fatalf("kicked %v, %d restarts: want one radio restart and no kick", w.kicked, restarts)
	}
}
