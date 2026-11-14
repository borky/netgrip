package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// A small, made-up router: a client zone with DHCP, a second client zone,
// a VPN zone without DHCP, an upstream zone (masquerading, PPPoE link plus
// a modem) and a routed uplink zone without masquerading.
const qTestFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='home'
firewall.@zone[0].network='home'
firewall.@zone[1]=zone
firewall.@zone[1].name='up'
firewall.@zone[1].network='uplink' 'uplink6'
firewall.@zone[1].masq='1'
firewall.@zone[1].device='tun9' 'wwan+'
firewall.@zone[2]=zone
firewall.@zone[2].name='guests'
firewall.@zone[2].network='guests'
firewall.@zone[3]=zone
firewall.@zone[3].name='vpn'
firewall.@zone[3].network='tunnel'
firewall.@zone[4]=zone
firewall.@zone[4].name='transit'
firewall.@zone[4].network='transit'
`

const qTestDhcp = `dhcp.home=dhcp
dhcp.home.interface='home'
dhcp.home.dhcp_option='6,192.0.2.53' '3,192.0.2.1'
dhcp.home.dns='2001:db8::53'
dhcp.guests=dhcp
dhcp.guests.interface='guests'
dhcp.up=dhcp
dhcp.up.interface='uplink'
dhcp.up.ignore='1'
dhcp.transit=dhcp
dhcp.transit.interface='transit'
`

var qTestIfaces = []ubus.InterfaceState{
	{Name: "uplink", Proto: "pppoe", Device: "eth9", L3Device: "pppoe-uplink", HasDefaultRoute: true},
	{Name: "uplink6", Proto: "qmi", Device: "/dev/cdc-wdm9"}, // a modem path is not a netdev
	{Name: "home", Device: "br-home"},
	{Name: "transit", Device: "eth8", HasDefaultRoute6: true},
}

func qZoneMap(zones []QZone) map[string]QZone {
	out := map[string]QZone{}
	for _, z := range zones {
		out[z.Name] = z
	}
	return out
}

func TestQZonesFromVPNServerIsNotAnUplink(t *testing.T) {
	fw := `firewall.@zone[0]=zone
firewall.@zone[0].name='peers'
firewall.@zone[0].network='rw'
firewall.@zone[0].masq='1'
firewall.@zone[1]=zone
firewall.@zone[1].name='backup'
firewall.@zone[1].network='lte'
firewall.@zone[1].masq='1'
firewall.@zone[2]=zone
firewall.@zone[2].name='vpnout'
firewall.@zone[2].network='tun' 'ovpn'
firewall.@zone[2].masq='1'
`
	netw := `network.rw=interface
network.rw.proto='wireguard'
network.rw.listen_port='51820'
network.@wireguard_rw[0]=wireguard_rw
network.@wireguard_rw[0].allowed_ips='10.99.0.2/32' 'fd99::2/128'
network.peer2=wireguard_rw
network.peer2.allowed_ips='10.99.0.3/32'
network.tun=interface
network.tun.proto='wireguard'
network.@wireguard_tun[0]=wireguard_tun
network.@wireguard_tun[0].allowed_ips='0.0.0.0/0' '::/0'
network.@wireguard_tun[0].route_allowed_ips='0'
network.ovpn=interface
network.ovpn.proto='none'
network.lte=interface
network.lte.proto='qmi'
`
	ifaces := []ubus.InterfaceState{
		{Name: "rw", Proto: "wireguard", Device: "wg9", Up: true},       // a VPN server: routes to its peers only
		{Name: "lte", Proto: "qmi", Device: "/dev/cdc-wdm9", Up: false}, // a backup uplink, down right now
		{Name: "tun", Proto: "wireguard", Device: "wg8", Up: true},      // a pbr client: no default route netifd knows of
		{Name: "ovpn", Proto: "none", Device: "tun0", Up: true},
	}
	servers := qVPNServerNetworks(netw)
	if !servers["rw"] || servers["tun"] || servers["lte"] || servers["ovpn"] {
		t.Fatalf("VPN servers: %v", servers)
	}
	got := qZoneMap(qZonesFrom(fw, "", nil, ifaces, servers))
	if got["peers"].Wan {
		t.Fatalf("a masquerading VPN server zone was taken for an uplink: %+v", got["peers"])
	}
	if !got["backup"].Wan || !got["vpnout"].Wan {
		t.Fatalf("a down modem or a VPN client without a default route is not an uplink: %+v", got)
	}
	devs, _ := qWanDevicesFrom(qZonesFrom(fw, "", nil, ifaces, servers), nil, ifaces)
	if strings.Join(devs, ",") != "tun0,wg8" {
		t.Fatalf("uplink devices: %v", devs)
	}
}

func TestQStickyWanKeepsAReconnectingLink(t *testing.T) {
	qWanStickyMu.Lock()
	old, oldNets := qWanSticky, qWanNets
	qWanSticky, qWanNets = map[string]time.Time{}, map[string]time.Time{}
	qWanStickyMu.Unlock()
	t.Cleanup(func() { qWanStickyMu.Lock(); qWanSticky, qWanNets = old, oldNets; qWanStickyMu.Unlock() })
	now := time.Now()
	zones := []QZone{{Name: "up", Networks: []string{"uplink"}, Wan: true}, {Name: "home", Networks: []string{"home", "guest"}}}
	up := []ubus.InterfaceState{{Name: "uplink", Device: "eth9", L3Device: "pppoe-uplink"}, {Name: "home", Device: "br-home"}}
	if got := qStickyWan(zones, up, []string{"eth9", "pppoe-uplink"}, now); strings.Join(got, ",") != "eth9,pppoe-uplink" {
		t.Fatalf("up: %v", got)
	}
	down := []ubus.InterfaceState{{Name: "uplink", Device: "eth9"}, {Name: "home", Device: "br-home"}}
	if got := qStickyWan(zones, down, []string{"eth9"}, now.Add(time.Minute)); strings.Join(got, ",") != "eth9,pppoe-uplink" {
		t.Fatalf("the PPPoE device left the set during a reconnect: %v", got)
	}
	// A zone that is an uplink by its default route alone is not one
	// while it reconnects: its devices stay for the grace time.
	zones[0].Wan = false
	if got := qStickyWan(zones, down, nil, now.Add(2*time.Minute)); strings.Join(got, ",") != "eth9,pppoe-uplink" {
		t.Fatalf("devices dropped during a brief loss of the default route: %v", got)
	}
	// ...and leave once it has passed.
	if got := qStickyWan(zones, down[1:], nil, now.Add(time.Minute+qWanGrace+time.Second)); len(got) != 0 {
		t.Fatalf("devices kept past the grace time: %v", got)
	}
	// A device an internal network takes over leaves at once.
	zones[0].Wan = true
	qStickyWan(zones, up, []string{"eth9", "pppoe-uplink"}, now)
	moved := []ubus.InterfaceState{{Name: "uplink", Device: "eth7"}, {Name: "guest", Device: "eth9"}}
	if got := qStickyWan(zones, moved, []string{"eth7"}, now.Add(time.Second)); strings.Join(got, ",") != "eth7,pppoe-uplink" {
		t.Fatalf("a device now used by an internal network kept in the uplink set: %v", got)
	}
}

func TestQVPNServerNetworksClientForms(t *testing.T) {
	netw := `network.split=interface
network.split.proto='wireguard'
network.@wireguard_split[0]=wireguard_split
network.@wireguard_split[0].allowed_ips='0.0.0.0/5' '8.0.0.0/7' '11.0.0.0/8' '10.8.0.1/32' '2000::/3'
network.onestr=interface
network.onestr.proto='wireguard'
network.p1=wireguard_onestr
network.p1.allowed_ips='0.0.0.0/0, ::/0'
network.spelled=interface
network.spelled.proto='wireguard'
network.p2=wireguard_spelled
network.p2.allowed_ips='0::0/0'
network.srv=interface
network.srv.proto='wireguard'
network.srv.listen_port='51820'
network.p3=wireguard_srv
network.p3.allowed_ips='10.99.0.2/32' '192.168.50.0/24'
network.p4=wireguard_srv
network.p4.allowed_ips='0.0.0.0/0'
network.p4.disabled='1'
network.p5=wireguard_srv
network.p5.allowed_ips='10.0.0.0/8'
`
	got := qVPNServerNetworks(netw)
	if got["split"] || got["onestr"] || got["spelled"] {
		t.Fatalf("a client tunnel was taken for a server: %v", got)
	}
	if !got["srv"] {
		t.Fatalf("a server with a disabled full-tunnel peer and a private site peer was taken for a client: %v", got)
	}
}

func TestQZonesFromFindsUplinksWithoutNames(t *testing.T) {
	got := qZoneMap(qZonesFrom(qTestFirewall, qTestDhcp, []string{"guests"}, qTestIfaces, nil))
	if !got["up"].Wan || got["up"].Suggested {
		t.Fatalf("masquerading zone: %+v", got["up"])
	}
	if !got["transit"].Wan || got["transit"].Suggested {
		t.Fatalf("a zone carrying a default route is an uplink even without masq: %+v", got["transit"])
	}
	if !got["home"].Suggested || !got["guests"].Suggested || got["vpn"].Suggested {
		t.Fatalf("suggestions: %+v", got)
	}
	if !got["guests"].Protected || got["home"].Protected {
		t.Fatalf("protected flags: %+v", got)
	}
	masq6 := qTestFirewall + "firewall.@zone[3].masq6='1'\n"
	if !qZoneMap(qZonesFrom(masq6, "", nil, nil, nil))["vpn"].Wan {
		t.Fatal("masq6 must mark an uplink")
	}
	if qZoneMap(qZonesFrom(masq6, "", nil, nil, map[string]bool{"tunnel": true}))["vpn"].Wan {
		t.Fatal("a VPN server's zone is not an uplink, masq6 or not")
	}
}

func TestQWanDevicesFrom(t *testing.T) {
	zones := qZonesFrom(qTestFirewall, "", nil, qTestIfaces, nil)
	devs, patterns := qWanDevicesFrom(zones, qZoneExtras(qTestFirewall), qTestIfaces)
	if strings.Join(devs, ",") != "eth8,eth9,pppoe-uplink,tun9" {
		t.Fatalf("wan devices: %v", devs)
	}
	if strings.Join(patterns, ",") != "wwan+" {
		t.Fatalf("patterns: %v", patterns)
	}
}

func TestQDHCPDNSServers(t *testing.T) {
	if got := strings.Join(qDHCPDNSServers(qTestDhcp), ","); got != "192.0.2.53,2001:db8::53" {
		t.Fatalf("dns servers: %s", got)
	}
}

func TestQActualZones(t *testing.T) {
	show := `firewall.netgrip_quarantine_table=include
firewall.netgrip_quarantine_input_0=include
firewall.netgrip_quarantine_input_0.chain='input_guests'
firewall.netgrip_quarantine_forward_0.chain='forward_guests'
firewall.netgrip_quarantine_input_1.chain='input_home'
firewall.other.chain='input_x'
`
	if got := strings.Join(qActualZones(show), ","); got != "guests,home" {
		t.Fatalf("actual zones: %s", got)
	}
}

func TestValidateZones(t *testing.T) {
	zones := qZonesFrom(qTestFirewall, qTestDhcp, nil, qTestIfaces, nil)
	for _, bad := range [][]string{nil, {"up"}, {"transit"}, {"nope"}, {"home'; drop"}} {
		if _, err := validateZones(bad, zones); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	got, err := validateZones([]string{"home", "guests", "home", "vpn"}, zones)
	if err != nil || strings.Join(got, ",") != "guests,home,vpn" {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestRenderQTable(t *testing.T) {
	rs := qRuleSet{Mode: "internet", Approved: []string{"02:00:00:00:00:0B", "02:00:00:00:00:0a", "bad", "02:00:00:00:00:0a"},
		Wan: []string{"pppoe-x", "eth9", "bad name"}, DNS: []string{"192.0.2.53", "2001:db8::53", "junk"}}
	out := renderQTable(rs)
	for _, want := range []string{
		`set netgrip_quarantine_approved { type ether_addr; elements = { 02:00:00:00:00:0a, 02:00:00:00:00:0b }; comment "netgrip quarantine: approved devices"; }`,
		`set netgrip_quarantine_uplinks { type ifname; elements = { "eth9", "pppoe-x" }; comment "netgrip quarantine: uplink interfaces (the internet)"; }`,
		`set netgrip_quarantine_paused { type nf_proto; flags timeout; comment "netgrip quarantine: protection paused until the timeout"; }`,
		"set netgrip_quarantine_dns4 { type ipv4_addr; elements = { 192.0.2.53 };",
		"set netgrip_quarantine_dns6 { type ipv6_addr; elements = { 2001:db8::53 };",
		"flags dynamic, timeout",
		"meta iiftype != ether return",
		"ct status dnat ct original proto-dst 53 return",
		"udp dport { 53, 67, 123, 547 } return",
		"oifname != @netgrip_quarantine_uplinks counter reject",
		"ip daddr @netgrip_quarantine_private4 counter reject",
		"ip6 daddr @netgrip_quarantine_private6 counter reject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	empty := renderQTable(qRuleSet{Mode: "nothing"})
	if strings.Contains(empty, "elements = {  }") || !strings.Contains(empty, `set netgrip_quarantine_approved { type ether_addr; comment "netgrip quarantine: approved devices"; }`) {
		t.Fatalf("empty sets:\n%s", empty)
	}
	if strings.Contains(empty, "oifname") {
		t.Fatal("nothing mode must not allow the WAN")
	}
}

// Everything the feature puts in the firewall says so: every rule, set and
// chain, and the jumps it adds to the zones' own chains.
func TestQEverythingIsLabelled(t *testing.T) {
	for _, mode := range []string{"internet", "nothing"} {
		rs := qRuleSet{Mode: mode, Approved: []string{"02:00:00:00:00:0a"}, Wan: []string{"eth9"}, DNS: []string{"192.0.2.53"}}
		for _, line := range strings.Split(renderQTable(rs)+renderQInputJump()+renderQForwardJump(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line == "}" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "set ") || strings.HasPrefix(line, "chain ") {
				if !strings.Contains(line, "netgrip_quarantine_") {
					t.Errorf("not named after the feature: %s", line)
				}
				if strings.HasPrefix(line, "chain ") {
					continue // the chain's comment is its first line
				}
			}
			if !strings.Contains(line, `comment "`+qCommentPrefix) {
				t.Errorf("no feature comment: %s", line)
			}
		}
	}
}

// The order is the safety: non-Ethernet traffic and approved devices leave
// before anything else, a pause "off" leaves before any refusal, and every
// chain ends in a refusal.
func TestQRuleOrder(t *testing.T) {
	for _, rules := range [][]string{
		qInputRules(qRuleSet{Mode: "internet"}),
		qForwardRules(qRuleSet{Mode: "nothing"}),
	} {
		if !strings.HasPrefix(rules[0], "meta iiftype != ether return") || !strings.HasPrefix(rules[1], "ether saddr @netgrip_quarantine_approved return") {
			t.Fatalf("head: %v", rules)
		}
		off, firstReject := -1, -1
		for i, r := range rules {
			if strings.Contains(r, "@netgrip_quarantine_paused return") {
				off = i
			}
			if strings.Contains(r, "reject") && firstReject < 0 {
				firstReject = i
			}
		}
		if off < 0 || firstReject < 0 || off > firstReject {
			t.Fatalf("pause must precede refusals: %v", rules)
		}
		if !strings.Contains(rules[len(rules)-1], "reject") && rules[len(rules)-1] != "return" {
			t.Fatalf("end: %v", rules)
		}
	}
	if last := qInputRules(qRuleSet{Mode: "internet"}); !strings.Contains(last[len(last)-1], "reject") {
		t.Fatal("input must end in a refusal")
	}
}

func TestQOffPauseScript(t *testing.T) {
	if s := qOffPauseScript(90); !strings.Contains(s, "flush set inet fw4 netgrip_quarantine_paused") || !strings.Contains(s, "ipv4 timeout 90s, ipv6 timeout 90s") {
		t.Fatalf("set: %s", s)
	}
	if s := qOffPauseScript(0); strings.Contains(s, "add element") {
		t.Fatalf("clear: %s", s)
	}
}

func TestRenderQRuntimeUpdateIsOneTransaction(t *testing.T) {
	out := renderQRuntimeUpdate(qRuleSet{Mode: "internet", Approved: []string{"02:00:00:00:00:01"}, Wan: []string{"eth9"}, DNS: []string{"192.0.2.53"}})
	for _, want := range []string{
		"flush chain inet fw4 netgrip_quarantine_input", "flush chain inet fw4 netgrip_quarantine_forward",
		"flush set inet fw4 netgrip_quarantine_approved", "add element inet fw4 netgrip_quarantine_approved { 02:00:00:00:00:01 }",
		`add element inet fw4 netgrip_quarantine_uplinks { "eth9" }`, "add element inet fw4 netgrip_quarantine_dns4 { 192.0.2.53 }", "table inet fw4 {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(renderQRuntimeUpdate(qRuleSet{Mode: "nothing"}), "add element") {
		t.Fatal("empty sets must not get an empty add element")
	}
}

func TestQIncludeOpsAreValidAndOwned(t *testing.T) {
	ops := qIncludeOps([]string{"netgrip_quarantine_table", "netgrip_quarantine_input_0"}, []string{"guests", "home"})
	for _, op := range ops {
		if err := executor.Validate(op); err != nil {
			t.Fatalf("op rejected by the executor: %v", err)
		}
	}
	joined := fmtOps(ops)
	for _, want := range []string{
		"uci_delete firewall.netgrip_quarantine_table", "uci_delete firewall.netgrip_quarantine_input_0",
		"uci_set firewall.netgrip_quarantine_table.position table-prepend",
		"uci_set firewall.netgrip_quarantine_input_0.chain input_guests",
		"uci_set firewall.netgrip_quarantine_forward_1.chain forward_home",
		"uci_commit firewall", "initd firewall reload",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Contains(fmtOps(qIncludeOps([]string{"netgrip_quarantine_table"}, nil)), "uci_set") {
		t.Fatal("disable must not create sections")
	}
}

func fmtOps(ops []executor.Op) string {
	s := ""
	for _, op := range ops {
		s += op.Kind + " " + strings.Join(op.Args, " ") + "\n"
	}
	return s
}

func TestQIncludeSectionsOnlyOwned(t *testing.T) {
	show := `firewall.netgrip_quarantine_table=include
firewall.netgrip_quarantine_table.path='/x'
firewall.netgrip_quarantine_input_0=include
firewall.user_include=include
firewall.netgrip_qos=rule
firewall.@include[0]=include
`
	if got := strings.Join(qIncludeSections(show), ","); got != "netgrip_quarantine_input_0,netgrip_quarantine_table" {
		t.Fatalf("got %s", got)
	}
}

func TestParseNftSetElements(t *testing.T) {
	raw := `{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"netgrip_quarantine_seen","elem":[
		"02:00:00:00:00:01",
		{"elem":{"val":"02:00:00:00:00:0A","timeout":3600,"expires":3500}}]}}]}`
	got, err := parseNftSetElementsTimed([]byte(raw))
	if err != nil || len(got) != 2 || got[1].Val != "02:00:00:00:00:0A" || got[1].Expires != 3500 {
		t.Fatalf("got %+v %v", got, err)
	}
	empty, err := parseNftSetElements([]byte(`{"nftables":[{"set":{"name":"x"}}]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty set: %v %v", empty, err)
	}
}

func TestParseNeighMAC(t *testing.T) {
	if got := parseNeighMAC("192.0.2.5 dev br-x lladdr 02:00:00:00:00:05 REACHABLE\n"); got != "02:00:00:00:00:05" {
		t.Fatalf("got %q", got)
	}
	if parseNeighMAC("192.0.2.6 dev br-x FAILED\n") != "" {
		t.Fatal("unresolved entry gave a MAC")
	}
	two := "192.0.2.7 dev a lladdr 02:00:00:00:00:07 REACHABLE\n192.0.2.7 dev b lladdr 02:00:00:00:00:08 STALE\n"
	if parseNeighMAC(two) != "" {
		t.Fatal("two different answers must be no answer")
	}
	if qNormalizeIP("fe80::1%br-x") != "fe80::1" || qNormalizeIP("[2001:db8::1]") != "2001:db8::1" {
		t.Fatal("zone or brackets not stripped")
	}
}

func TestWriteFileDurable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := writeFileDurable(p, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileDurable(p, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "b" {
		t.Fatalf("content %q", b)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
}

// ---- Flow tests with every system call faked ----

type qFake struct {
	t         *testing.T
	sections  map[string]map[string]string // owned include sections: options
	applied   [][]executor.Op
	nft       []string
	checkErr  error
	applyErr  error
	verify    error
	showErr   error
	seen      []qElem
	live      bool
	mu        sync.Mutex
	notified  []string
	requester string
}

func newQFake(t *testing.T) *qFake {
	t.Helper()
	dir := t.TempDir()
	f := &qFake{t: t, sections: map[string]map[string]string{}, requester: "02:00:00:00:00:10"}
	oldDir, oldState := quarantineDir, qStatePath
	quarantineDir = filepath.Join(dir, "q")
	qStatePath = filepath.Join(dir, "quarantine.json")
	oldMissing, oldFlush, oldFull, oldForce := qMissingPolls, qLastFlush, qLastFullCheck, qForceFull
	qWanStickyMu.Lock()
	oldSticky, oldNets := qWanSticky, qWanNets
	qWanSticky, qWanNets = map[string]time.Time{}, map[string]time.Time{}
	qWanStickyMu.Unlock()
	oldBudget, oldUsed, oldSum := qBudgetStart, qBudgetUsed, qBudgetSummaries
	qMissingPolls, qLastFlush, qLastFullCheck, qForceFull = 0, time.Time{}, time.Time{}, false
	oDue, oFirst, oNow := qRestartDue, qRestartFirst, qNowFn
	qRestartDue, qRestartFirst = map[string]time.Time{}, map[string]time.Time{}
	t.Cleanup(func() { qRestartDue, qRestartFirst, qNowFn = oDue, oFirst, oNow })
	oWireless, oKickDelay := qWirelessShowFn, qKickDelay
	qWirelessShowFn = func() (string, error) { return uciShowFn("wireless") }
	qKickDelay = 0
	t.Cleanup(func() { qWirelessShowFn, qKickDelay = oWireless, oKickDelay })
	qBudgetStart, qBudgetUsed, qBudgetSummaries = time.Time{}, 0, 0
	t.Cleanup(func() {
		quarantineDir, qStatePath = oldDir, oldState
		qMissingPolls, qLastFlush, qLastFullCheck, qForceFull = oldMissing, oldFlush, oldFull, oldForce
		qWanStickyMu.Lock()
		qWanSticky, qWanNets = oldSticky, oldNets
		qWanStickyMu.Unlock()
		qBudgetStart, qBudgetUsed, qBudgetSummaries = oldBudget, oldUsed, oldSum
	})

	oShow, oDump, oNft, oApply, oVerify, oReq, oApp, oIdent, oSeen, oNotify, oList, oChan, oDrift :=
		uciShowFn, dumpInterfacesFn, nftRunFn, applyQIncludes, qVerifyLive, requesterMACFn, qApplicable, qIdentities, qSeenFn, qNotifyFn, listClientsFn, qChannelsFn, qLiveDrifted
	t.Cleanup(func() {
		uciShowFn, dumpInterfacesFn, nftRunFn, applyQIncludes, qVerifyLive, requesterMACFn, qApplicable, qIdentities, qSeenFn, qNotifyFn, listClientsFn, qChannelsFn, qLiveDrifted =
			oShow, oDump, oNft, oApply, oVerify, oReq, oApp, oIdent, oSeen, oNotify, oList, oChan, oDrift
	})

	uciShowFn = func(pkg string) (string, error) {
		if pkg == "dhcp" {
			return qTestDhcp, nil
		}
		if pkg == "network" {
			return "", nil
		}
		if f.showErr != nil {
			return "", f.showErr
		}
		s := qTestFirewall
		names := make([]string, 0, len(f.sections))
		for sec := range f.sections {
			names = append(names, sec)
		}
		sort.Strings(names)
		for _, sec := range names {
			s += "firewall." + sec + "=include\n"
			for opt, val := range f.sections[sec] {
				s += "firewall." + sec + "." + opt + "='" + val + "'\n"
			}
		}
		return s, nil
	}
	dumpInterfacesFn = func() ([]ubus.InterfaceState, error) { return qTestIfaces, nil }
	nftRunFn = func(stdin string, args ...string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(cmd, "-c "):
			return nil, f.checkErr
		case strings.HasPrefix(cmd, "list chain"):
			if f.live {
				return []byte("chain"), nil
			}
			return nil, errors.New("no chain")
		case strings.HasPrefix(cmd, "-j list set"):
			return []byte(`{"nftables":[]}`), nil
		}
		f.nft = append(f.nft, cmd+"\n"+stdin)
		return nil, nil
	}
	applyQIncludes = func(ops []executor.Op) error {
		f.applied = append(f.applied, ops)
		if f.applyErr != nil {
			return f.applyErr
		}
		for _, op := range ops {
			key := strings.TrimPrefix(op.Args[0], "firewall.")
			sec, opt, hasOpt := strings.Cut(key, ".")
			switch {
			case op.Kind == "uci_delete":
				delete(f.sections, sec)
			case op.Kind == "uci_set" && !hasOpt:
				f.sections[sec] = map[string]string{}
			case op.Kind == "uci_set":
				f.sections[sec][opt] = op.Args[1]
			}
		}
		f.live = len(f.sections) > 0
		return nil
	}
	qVerifyLive = func([]string, string) error { return f.verify }
	requesterMACFn = func(ip string) string {
		if qNormalizeIP(ip) == "192.0.2.10" {
			return f.requester
		}
		return ""
	}
	qApplicable = func() (bool, string) { return true, "" }
	qIdentities = func() qIdent {
		return qIdent{arp: map[string]string{"02:00:00:00:00:99": "192.0.2.99"}, leases: map[string]ubus.Lease{}, meta: map[string]ClientMeta{}}
	}
	qSeenFn = func() ([]qElem, error) {
		// The set lives in the same included table as the chains.
		if !f.live {
			return nil, errors.New("no such set")
		}
		return f.seen, nil
	}
	qNotifyFn = func(_, _, plain string, _ bool) { f.mu.Lock(); f.notified = append(f.notified, plain); f.mu.Unlock() }
	listClientsFn = func(string) []Client { return nil }
	qChannelsFn = func() bool { return false }
	qLiveDrifted = func(*qState, qRouter, time.Time) bool { return false }
	return f
}

func (f *qFake) notifiedCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.notified) }

func (f *qFake) notifiedText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.notified, "\n")
}

func (f *qFake) enable(t *testing.T, mode string, zones ...string) {
	t.Helper()
	if _, err := QuarantineEnable(QEnableRequest{Mode: mode, Zones: zones}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineEnableAlwaysTrustsTheRequester(t *testing.T) {
	f := newQFake(t)
	p, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}, Approve: []QApproveItem{{MAC: "02:00:00:00:00:20", Name: "nas"}}}, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || !p.Active {
		t.Fatalf("probe: %+v", p)
	}
	if !qZoneMap(p.Zones)["home"].Protected {
		t.Fatal("protection must be read back from the firewall config")
	}
	st := loadQState()
	if _, ok := st.Approved["02:00:00:00:00:10"]; !ok {
		t.Fatal("the panel user's device was not approved")
	}
	if st.Approved["02:00:00:00:00:20"].Name != "nas" {
		t.Fatalf("baseline: %+v", st.Approved)
	}
	for _, file := range []string{qTableFile(), qInputFile(), qForwardFile()} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("missing include file %s", file)
		}
	}
	if f.sections["netgrip_quarantine_input_0"]["chain"] != "input_home" || f.sections["netgrip_quarantine_forward_0"]["chain"] != "forward_home" {
		t.Fatalf("sections: %v", f.sections)
	}
}

func TestQuarantineEnableRefusesWithoutRequester(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "198.51.100.7"); err == nil {
		t.Fatal("enabled without knowing the panel user's device")
	}
	if len(f.applied) != 0 {
		t.Fatal("something was changed")
	}
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}, AllowNoRequester: true}, "198.51.100.7"); err != nil {
		t.Fatalf("explicit opt-in refused: %v", err)
	}
}

func TestQuarantineEnableKernelCheckFailureChangesNothing(t *testing.T) {
	f := newQFake(t)
	f.checkErr = errors.New("unsupported")
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "192.0.2.10"); err == nil {
		t.Fatal("no error")
	}
	if len(f.applied) != 0 {
		t.Fatal("firewall touched after a failed check")
	}
	if _, err := os.Stat(qTableFile()); err == nil {
		t.Fatal("include file written after a failed check")
	}
	if loadQState().Enabled {
		t.Fatal("recorded as enabled")
	}
}

func TestQuarantineEnableUndoesAFailedStart(t *testing.T) {
	f := newQFake(t)
	f.verify = errors.New("chains missing")
	if _, err := QuarantineEnable(QEnableRequest{Mode: "nothing", Zones: []string{"home"}}, "192.0.2.10"); err == nil {
		t.Fatal("no error")
	}
	if len(f.sections) != 0 {
		t.Fatalf("sections left behind: %v", f.sections)
	}
	if loadQState().Enabled {
		t.Fatal("still recorded as enabled")
	}
	if _, err := os.Stat(qInputFile()); err == nil {
		t.Fatal("include file left behind")
	}
}

func TestQuarantineEnableRefusesOnAFailedConfigRead(t *testing.T) {
	f := newQFake(t)
	f.showErr = errors.New("uci busy")
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "192.0.2.10"); err == nil {
		t.Fatal("enabled on a failed read")
	}
	if len(f.applied) != 0 {
		t.Fatal("firewall touched")
	}
}

func TestQuarantineEnableRejectsBadInput(t *testing.T) {
	newQFake(t)
	for _, req := range []QEnableRequest{
		{Mode: "open", Zones: []string{"home"}},
		{Mode: "internet", Zones: []string{"up"}},
		{Mode: "internet", Zones: []string{"transit"}},
		{Mode: "internet", Zones: []string{"home"}, Approve: []QApproveItem{{MAC: "zz"}}},
	} {
		if _, err := QuarantineEnable(req, "192.0.2.10"); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
}

func TestQuarantineSetZonesKeepsTheRequesterAndRollsBack(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	// The admin is now on a device the quarantine does not know yet.
	f.requester = "02:00:00:00:00:44"
	if _, err := QuarantineSetZones([]string{"home", "guests"}, "192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadQState().Approved["02:00:00:00:00:44"]; !ok {
		t.Fatal("changing zones did not keep the panel user's device")
	}
	if got := strings.Join(qActualZones(mustShow(t)), ","); got != "guests,home" {
		t.Fatalf("zones: %s", got)
	}
	// A failed verification puts the previous zones back.
	f.verify = errors.New("no jump")
	if _, err := QuarantineSetZones([]string{"home"}, "192.0.2.10", false); err == nil {
		t.Fatal("no error")
	}
	if got := strings.Join(qActualZones(mustShow(t)), ","); got != "guests,home" {
		t.Fatalf("previous zones not restored: %s", got)
	}
	if got := strings.Join(loadQState().Zones, ","); got != "guests,home" {
		t.Fatalf("intent changed by a failed change: %s", got)
	}
	f.verify = nil
	if _, err := QuarantineSetZones([]string{"home"}, "198.51.100.7", false); err == nil {
		t.Fatal("changed zones without knowing the panel user's device")
	}
}

func mustShow(t *testing.T) string {
	t.Helper()
	s, err := uciShowFn("firewall")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQuarantineRevokeGuards(t *testing.T) {
	newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}, Approve: []QApproveItem{{MAC: "02:00:00:00:00:20"}}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineRevoke("02:00:00:00:00:10", "192.0.2.10", true); err == nil {
		t.Fatal("revoked the panel user's own device")
	}
	if _, err := QuarantineRevoke("02:00:00:00:00:20", "198.51.100.7", false); err == nil {
		t.Fatal("revoked while the panel user's device is unknown")
	}
	if _, err := QuarantineRevoke("02:00:00:00:00:20", "192.0.2.10", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadQState().Approved["02:00:00:00:00:20"]; ok {
		t.Fatal("not revoked")
	}
}

func TestQuarantineDisableRemovesEverythingButKeepsApprovals(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home", "guests")
	if _, err := QuarantineDisable(); err != nil {
		t.Fatal(err)
	}
	if len(f.sections) != 0 {
		t.Fatalf("sections left: %v", f.sections)
	}
	if _, err := os.Stat(qTableFile()); err == nil {
		t.Fatal("include file left")
	}
	st := loadQState()
	if st.Enabled || len(st.Approved) == 0 {
		t.Fatalf("state: %+v", st)
	}
}

func TestQuarantineDisableKeepsFilesWhenTheFirewallChangeFails(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	f.applyErr = errors.New("reload failed")
	p, err := QuarantineDisable()
	if err == nil {
		t.Fatal("no error")
	}
	if _, err := os.Stat(qInputFile()); err != nil {
		t.Fatal("files removed while the sections still point at them")
	}
	if !p.Enabled || !loadQState().Enabled {
		t.Fatal("recorded as off while the rules are still enforced")
	}
}

func TestQReadFailuresDecideNothing(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	dumpInterfacesFn = func() ([]ubus.InterfaceState, error) { return nil, errors.New("ubus down") }
	if _, err := readQRouter(); err == nil {
		t.Fatal("a failed interface read was taken as empty")
	}
	f.nft = nil
	qLiveDrifted = func(*qState, qRouter, time.Time) bool { return true }
	qPoll(time.Now())
	if len(f.nft) != 0 {
		t.Fatalf("synced from a failed read: %v", f.nft)
	}
}

func TestQPollRecordsAndNotifiesOnceEvenAfterForget(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qChannelsFn = func() bool { return true }
	f.seen = []qElem{{Val: "02:00:00:00:00:99", Expires: 3000}, {Val: "02:00:00:00:00:10"}}
	now := time.Now()
	qPoll(now)
	qPoll(now.Add(5 * time.Second))
	st := loadQState()
	if _, ok := st.Pending["02:00:00:00:00:10"]; ok {
		t.Fatal("an approved device was listed as pending")
	}
	p := st.Pending["02:00:00:00:00:99"]
	// The second poll's set entry is 5 s fresher: last seen is now-595.
	if p.IP != "192.0.2.99" || p.LastSeen != now.Unix()+5-600 {
		t.Fatalf("pending: %+v (last seen must come from the set's expiry)", p)
	}
	qWaitFor(t, func() bool { return f.notifiedCount() >= 1 })
	if _, err := QuarantineForget("02:00:00:00:00:99"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.nft, "\n"), "delete element inet fw4 netgrip_quarantine_seen { 02:00:00:00:00:99 }") {
		t.Fatal("forget did not clear the live record")
	}
	qPoll(now.Add(10 * time.Second))
	time.Sleep(30 * time.Millisecond)
	if f.notifiedCount() != 1 {
		t.Fatalf("notified %d times", f.notifiedCount())
	}
}

func TestQPollBurstIsSummarised(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qChannelsFn = func() bool { return true }
	for i := 0; i < 20; i++ {
		f.seen = append(f.seen, qElem{Val: "02:00:00:00:01:" + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])})
	}
	qPoll(time.Now())
	qWaitFor(t, func() bool { return f.notifiedCount() == qNotifyPerPoll+1 })
	time.Sleep(30 * time.Millisecond)
	if f.notifiedCount() != qNotifyPerPoll+1 || !strings.Contains(f.notifiedText(), "17 more") {
		t.Fatalf("notifications: %d\n%s", f.notifiedCount(), f.notifiedText())
	}
}

func TestQNotifyBudget(t *testing.T) {
	newQFake(t)
	now := time.Now()
	dev := func(i int) QDevice { return QDevice{MAC: "02:00:00:00:03:0" + string("0123456789"[i%10])} }
	sent, summaries := 0, 0
	for poll := 0; poll < 50; poll++ {
		for _, d := range qNotifyBudget([]QDevice{dev(poll), dev(poll + 1), dev(poll + 2), dev(poll + 3), dev(poll + 4)}, now) {
			if d.MAC == "" {
				summaries++
			} else {
				sent++
			}
		}
	}
	if sent != qNotifyPerHour || summaries != qSummariesPerHour {
		t.Fatalf("sent %d, summaries %d in an hour", sent, summaries)
	}
	if got := qNotifyBudget([]QDevice{dev(1)}, now.Add(61*time.Minute)); len(got) != 1 || got[0].MAC == "" {
		t.Fatalf("budget not renewed: %+v", got)
	}
}

func TestQPollSparesTheFlash(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	f.seen = []qElem{{Val: "02:00:00:00:00:99", Expires: 3500}}
	now := time.Now()
	qPoll(now) // new device: saved
	before, _ := os.Stat(qStatePath)
	time.Sleep(20 * time.Millisecond)
	f.seen = []qElem{{Val: "02:00:00:00:00:99", Expires: 3590}} // only "last seen" moves
	qPoll(now.Add(5 * time.Second))
	after, _ := os.Stat(qStatePath)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("a last-seen refresh was written straight away")
	}
	qPoll(now.Add(qFlushEvery + time.Minute))
	later, _ := os.Stat(qStatePath)
	if later.ModTime().Equal(before.ModTime()) {
		t.Fatal("last-seen refreshes are never written")
	}
}

func TestQPollMACFloodSparesTheFlash(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	now := time.Now()
	qPoll(now)
	base, _ := os.Stat(qStatePath)
	writes, late := 0, 0
	last := base.ModTime()
	for i := 0; i < 60; i++ { // five minutes of a new random MAC every poll
		time.Sleep(2 * time.Millisecond)
		f.seen = append(f.seen, qElem{Val: fmt.Sprintf("02:00:00:00:%02x:%02x", 0x40+i/256, i%256), Expires: 3600})
		qPoll(now.Add(time.Duration(i+1) * qPollInterval))
		if st, _ := os.Stat(qStatePath); !st.ModTime().Equal(last) {
			writes++
			if i >= qNotifyPerHour {
				late++
			}
			last = st.ModTime()
		}
	}
	// Each device announced on its own is written (the hourly budget
	// bounds that); once the budget is spent the flood writes nothing.
	if writes > qNotifyPerHour+1 || late > 1 {
		t.Fatalf("%d flash writes in five minutes of new MACs, %d after the budget was spent", writes, late)
	}
	// The panel still sees every device at once.
	if p := ProbeQuarantine(); len(p.Pending) != 60 {
		t.Fatalf("pending in memory: %d, want 60", len(p.Pending))
	}
	// And they reach the flash once the interval has passed.
	qPoll(now.Add(qFlushEvery + 2*time.Minute))
	raw, _ := os.ReadFile(qStatePath)
	var st qState
	_ = json.Unmarshal(raw, &st)
	if len(st.Pending) != 60 {
		t.Fatalf("pending on flash: %d, want 60", len(st.Pending))
	}
}

func TestQLearnedApprovalWrittenAtOnce(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	f.seen = []qElem{{Val: "02:00:00:00:00:77"}}
	qPoll(time.Now())
	raw, _ := os.ReadFile(qStatePath)
	var st qState
	_ = json.Unmarshal(raw, &st)
	if _, ok := st.Approved["02:00:00:00:00:77"]; !ok {
		t.Fatal("a learned approval was not written to the flash at once")
	}
}

func TestQLearningPauseApprovesOnlyNewDevices(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	f.seen = []qElem{{Val: "02:00:00:00:00:66"}}
	qPoll(time.Now()) // already waiting before the pause
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	f.seen = []qElem{{Val: "02:00:00:00:00:66"}, {Val: "02:00:00:00:00:31"}}
	qPoll(time.Now())
	st := loadQState()
	if st.Approved["02:00:00:00:00:31"].Via != "pause" {
		t.Fatalf("new device not learned: %+v", st.Approved)
	}
	if _, ok := st.Approved["02:00:00:00:00:66"]; ok {
		t.Fatal("a device already waiting was approved by the pause")
	}
	qChannelsFn = func() bool { return true }
	qPoll(time.Now().Add(31 * time.Minute))
	if loadQState().Pause.Until != 0 {
		t.Fatal("the pause did not end")
	}
	qWaitFor(t, func() bool { return strings.Contains(f.notifiedText(), "02:00:00:00:00:31") })
}

func TestQLearningPauseIsCapped(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < qMaxLearned+10; i++ {
		f.seen = append(f.seen, qElem{Val: "02:00:00:00:02:" + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])})
	}
	qPoll(time.Now())
	if got := len(loadQState().Pause.Learned); got != qMaxLearned {
		t.Fatalf("learned %d", got)
	}
}

func TestQPauseOffLivesInTheKernel(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	f.nft = nil
	if _, err := QuarantinePause(10, "off"); err != nil {
		t.Fatal(err)
	}
	live := strings.Join(f.nft, "\n")
	if !strings.Contains(live, "add element inet fw4 netgrip_quarantine_paused { ipv4 timeout") {
		t.Fatalf("pause off not set in the kernel:\n%s", live)
	}
	table, _ := os.ReadFile(qTableFile())
	if strings.Contains(string(table), "ipv4 timeout") {
		t.Fatal("a reload must start without the pause")
	}
	if _, err := QuarantinePause(10, "bogus"); err == nil {
		t.Fatal("bad pause kind accepted")
	}
}

func TestQResumeKeepsThePanelUser(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	if _, err := QuarantinePause(10, "off"); err != nil {
		t.Fatal(err)
	}
	f.requester = "02:00:00:00:00:55" // joined during the pause
	if _, err := QuarantineResume("192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if loadQState().Approved["02:00:00:00:00:55"].Via != "panel" {
		t.Fatal("resuming did not keep the panel user's device")
	}
}

func TestQPollNoticesARevertOnlyWhenSure(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	f.showErr = errors.New("uci busy")
	qPoll(time.Now())
	qPoll(time.Now())
	if !loadQState().Enabled {
		t.Fatal("a failed read turned the feature off")
	}
	f.showErr = nil
	f.sections = map[string]map[string]string{} // the confirm window restored the old firewall
	qPoll(time.Now())                           // chains still loaded: not yet
	if !loadQState().Enabled {
		t.Fatal("turned off while the chains are still live")
	}
	f.live = false
	qPoll(time.Now())
	if !loadQState().Enabled {
		t.Fatal("turned off after a single miss")
	}
	qPoll(time.Now())
	if loadQState().Enabled {
		t.Fatal("still recorded as enabled after the feature left the firewall")
	}
}

func TestQApproveDropsAMACUsedAsName(t *testing.T) {
	newQFake(t)
	if qDeviceName("02:00:00:00:00:51", "02:00:00:00:00:51") != "" || qDeviceName("02:00:00:00:00:51", "02:00:00:00:00:51 ") != "" {
		t.Fatal("a MAC stand-in was kept as a name")
	}
	if qDeviceName("02:00:00:00:00:5a", "02:00:00:00:00:5A") != "" || qDeviceName("02:00:00:00:00:51", "Kitchen plug") != "Kitchen plug" {
		t.Fatal("an upper-case MAC was kept, or a real name dropped")
	}
}

func TestQPollRetriesAFailedFullCheckNextPoll(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	now := time.Now()
	qPoll(now) // a full check
	reads := 0
	show := uciShowFn
	uciShowFn = func(pkg string) (string, error) {
		if pkg == "firewall" {
			reads++
			if reads == 1 {
				return "", errors.New("uci busy")
			}
		}
		return show(pkg)
	}
	qPoll(now.Add(qFullCheckEvery)) // due, fails
	qPoll(now.Add(qFullCheckEvery + qPollInterval))
	if reads != 2 {
		t.Fatalf("a failed full check was retried after %d reads, want on the next poll", reads)
	}
}

func TestQPollPersistentSyncFailureKeepsThePace(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qLiveDrifted = func(*qState, qRouter, time.Time) bool { return true }
	nft := nftRunFn
	nftRunFn = func(stdin string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-c" {
			return nil, errors.New("rules refused")
		}
		return nft(stdin, args...)
	}
	reads := 0
	show := uciShowFn
	uciShowFn = func(pkg string) (string, error) {
		if pkg == "firewall" {
			reads++
		}
		return show(pkg)
	}
	now := time.Now()
	for i := 0; i < 12; i++ { // one minute
		qPoll(now.Add(time.Duration(i) * qPollInterval))
	}
	// The first check, one retry, and the next 30 s check.
	if reads > 3 {
		t.Fatalf("%d full checks in a minute of a failing sync", reads)
	}
}

func TestQPollRenamesTheFirstReleasesRules(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	// The firewall as the first release left it.
	legacy := map[string]map[string]string{}
	for name, sec := range f.sections {
		old := strings.NewReplacer("netgrip_quarantine_input_", "netgrip_q_in_", "netgrip_quarantine_forward_", "netgrip_q_fw_", "netgrip_quarantine_table", "netgrip_q_table").Replace(name)
		legacy[old] = sec
	}
	f.sections = legacy
	fw, _ := uciShowFn("firewall")
	if got := qActualZones(fw); strings.Join(got, ",") != "home" {
		t.Fatalf("legacy sections not read as the feature's own: %v", got)
	}
	qPoll(time.Now())
	for name := range f.sections {
		if !strings.HasPrefix(name, "netgrip_quarantine_") {
			t.Fatalf("legacy section left behind: %v", f.sections)
		}
	}
	if len(f.sections) != 3 || f.sections["netgrip_quarantine_input_0"]["chain"] != "input_home" {
		t.Fatalf("renamed sections: %v", f.sections)
	}
	if !loadQState().Enabled {
		t.Fatal("the rename turned the feature off")
	}
	cmds := strings.Join(f.nft, "\n")
	for _, want := range []string{"delete chain inet fw4 netgrip_q_input", "delete chain inet fw4 netgrip_q_forward", "delete set inet fw4 netgrip_q_ok", "delete set inet fw4 netgrip_q_off"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("old object not removed: %s", want)
		}
	}
	if strings.Index(cmds, "delete set inet fw4 netgrip_q_ok") < strings.Index(cmds, "delete chain inet fw4 netgrip_q_forward") {
		t.Error("a set was deleted before the chains that use it")
	}
}

func TestQPollFullCheckIsPaced(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	reads := 0
	show := uciShowFn
	uciShowFn = func(pkg string) (string, error) {
		if pkg == "firewall" {
			reads++
		}
		return show(pkg)
	}
	now := time.Now()
	for i := 0; i < 12; i++ { // one minute of polls
		qPoll(now.Add(time.Duration(i) * qPollInterval))
	}
	if reads != 2 {
		t.Fatalf("%d full router reads in a minute, want 2", reads)
	}
	// A learning-pause approval does not wait for the next full check.
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	reads = 0
	f.seen = []qElem{{Val: "02:00:00:00:00:78"}}
	qPoll(now.Add(61 * time.Second))
	f.seen = []qElem{{Val: "02:00:00:00:00:79"}}
	qPoll(now.Add(63 * time.Second))
	if reads != 2 {
		t.Fatalf("%d full reads for two learned devices, want one each", reads)
	}
}

func TestQPollFollowsTheActualZones(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home", "guests")
	// A revert restored an older firewall that only protected "home".
	f.sections = map[string]map[string]string{}
	_ = applyQIncludes(qIncludeOps(nil, []string{"home"}))
	qPoll(time.Now())
	if got := strings.Join(loadQState().Zones, ","); got != "home" {
		t.Fatalf("zones: %s", got)
	}
}

func TestQPollReconcilesDrift(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	drift := true
	qLiveDrifted = func(*qState, qRouter, time.Time) bool { return drift }
	f.nft = nil
	qPoll(time.Now())
	if !strings.Contains(strings.Join(f.nft, "\n"), "flush chain inet fw4 netgrip_quarantine_input") {
		t.Fatal("drift was not repaired")
	}
	drift = false
	f.nft = nil
	qPoll(time.Now())
	if len(f.nft) != 0 {
		t.Fatalf("resynced without drift: %v", f.nft)
	}
}

func TestQuarantineKeepCheck(t *testing.T) {
	f := newQFake(t)
	if err := QuarantineKeepCheck("192.0.2.10"); err != nil {
		t.Fatal("off: must not interfere")
	}
	f.enable(t, "internet", "home")
	// Unapproved in the live set (faked as empty) but never recorded by the
	// quarantine: e.g. on an unprotected network. Must not block Keep.
	if err := QuarantineKeepCheck("192.0.2.10"); err != nil {
		t.Fatalf("blocked a device the quarantine is not refusing: %v", err)
	}
	f.seen = []qElem{{Val: "02:00:00:00:00:10"}}
	if err := QuarantineKeepCheck("192.0.2.10"); err == nil {
		t.Fatal("kept a change while the panel user is being quarantined")
	}
	if err := QuarantineKeepCheck("198.51.100.7"); err != nil {
		t.Fatal("an unknown device cannot be judged and must not block")
	}
	if _, err := QuarantinePause(10, "off"); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineKeepCheck("192.0.2.10"); err != nil {
		t.Fatal("blocked Keep during a pause off, when nothing is refused")
	}
}

func TestQOffPauseDoesNotAnnounce(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qChannelsFn = func() bool { return true }
	if _, err := QuarantinePause(10, "off"); err != nil {
		t.Fatal(err)
	}
	f.seen = []qElem{{Val: "02:00:00:00:00:77"}}
	qPoll(time.Now())
	time.Sleep(30 * time.Millisecond)
	if f.notifiedCount() != 0 {
		t.Fatal("announced as quarantined while nothing is refused")
	}
	if _, ok := loadQState().Pending["02:00:00:00:00:77"]; !ok {
		t.Fatal("not recorded")
	}
	qPoll(time.Now().Add(11 * time.Minute)) // the pause has ended
	qWaitFor(t, func() bool { return f.notifiedCount() == 1 })
}

func TestQLearningPauseExcludesKnownDevices(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "nothing", "home")
	st := loadQState()
	st.Notified["02:00:00:00:00:81"] = time.Now().Unix() // announced, then forgotten
	_ = saveQState(st)
	f.seen = []qElem{{Val: "02:00:00:00:00:82"}} // recorded, not polled yet
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	f.seen = []qElem{{Val: "02:00:00:00:00:81"}, {Val: "02:00:00:00:00:82"}, {Val: "02:00:00:00:00:83"}}
	qPoll(time.Now())
	a := loadQState().Approved
	if _, ok := a["02:00:00:00:00:81"]; ok {
		t.Fatal("a forgotten device was learned")
	}
	if _, ok := a["02:00:00:00:00:82"]; ok {
		t.Fatal("a device recorded before the pause was learned")
	}
	if a["02:00:00:00:00:83"].Via != "pause" {
		t.Fatal("a new device was not learned")
	}
}

func TestQPrunePending(t *testing.T) {
	now := time.Now()
	st := &qState{Pending: map[string]QPending{
		"02:00:00:00:00:01": {LastSeen: now.Add(-8 * 24 * time.Hour).Unix()},
		"02:00:00:00:00:02": {LastSeen: now.Unix()},
	}, Notified: map[string]int64{"02:00:00:00:00:03": now.Add(-8 * 24 * time.Hour).Unix()}}
	if !qPrunePending(st, now) || len(st.Pending) != 1 || len(st.Notified) != 0 {
		t.Fatalf("pending: %+v notified: %+v", st.Pending, st.Notified)
	}
}

func qWaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
