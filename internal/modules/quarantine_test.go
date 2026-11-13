package modules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/ubus"
)

// A small, made-up router: a client zone with DHCP, a second client zone,
// a zone without DHCP and an upstream zone (masquerading) whose networks
// are a PPPoE link and a DHCP WAN.
const qTestFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='home'
firewall.@zone[0].network='home'
firewall.@zone[1]=zone
firewall.@zone[1].name='up'
firewall.@zone[1].network='uplink' 'uplink6'
firewall.@zone[1].masq='1'
firewall.@zone[1].device='tun9'
firewall.@zone[2]=zone
firewall.@zone[2].name='guests'
firewall.@zone[2].network='guests'
firewall.@zone[3]=zone
firewall.@zone[3].name='vpn'
firewall.@zone[3].network='tunnel'
`

const qTestDhcp = `dhcp.home=dhcp
dhcp.home.interface='home'
dhcp.guests=dhcp
dhcp.guests.interface='guests'
dhcp.up=dhcp
dhcp.up.interface='uplink'
dhcp.up.ignore='1'
`

func TestQZonesFrom(t *testing.T) {
	zones := qZonesFrom(qTestFirewall, qTestDhcp, []string{"guests"})
	got := map[string]QZone{}
	for _, z := range zones {
		got[z.Name] = z
	}
	if !got["up"].Wan || got["up"].Suggested {
		t.Fatalf("upstream zone: %+v", got["up"])
	}
	if !got["home"].Suggested || !got["guests"].Suggested || got["vpn"].Suggested {
		t.Fatalf("suggestions: %+v", zones)
	}
	if !got["guests"].Protected || got["home"].Protected {
		t.Fatalf("protected flags: %+v", zones)
	}
}

func TestQWanDevicesFrom(t *testing.T) {
	zones := qZonesFrom(qTestFirewall, "", nil)
	ifaces := []ubus.InterfaceState{
		{Name: "uplink", Device: "eth9", L3Device: "pppoe-uplink"},
		{Name: "uplink6", Device: "/dev/cdc-wdm9"}, // a modem path is not a netdev
		{Name: "home", Device: "br-home"},
	}
	got := qWanDevicesFrom(zones, qZoneDevices(qTestFirewall), ifaces)
	if strings.Join(got, ",") != "eth9,pppoe-uplink,tun9" {
		t.Fatalf("wan devices: %v", got)
	}
}

func TestValidateZones(t *testing.T) {
	zones := qZonesFrom(qTestFirewall, qTestDhcp, nil)
	if _, err := validateZones(nil, zones); err == nil {
		t.Fatal("no zone accepted")
	}
	if _, err := validateZones([]string{"up"}, zones); err == nil {
		t.Fatal("an upstream zone was accepted")
	}
	if _, err := validateZones([]string{"nope"}, zones); err == nil {
		t.Fatal("an unknown zone was accepted")
	}
	if _, err := validateZones([]string{"home'; drop"}, zones); err == nil {
		t.Fatal("a malformed zone name was accepted")
	}
	got, err := validateZones([]string{"home", "guests", "home"}, zones)
	if err != nil || strings.Join(got, ",") != "guests,home" {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestRenderQTable(t *testing.T) {
	rs := qRuleSet{Mode: "internet", Approved: []string{"02:00:00:00:00:0B", "02:00:00:00:00:0a", "bad", "02:00:00:00:00:0a"}, Wan: []string{"pppoe-x", "eth9", "bad name"}}
	out := renderQTable(rs)
	for _, want := range []string{
		"set netgrip_q_ok { type ether_addr; elements = { 02:00:00:00:00:0a, 02:00:00:00:00:0b }; }",
		`set netgrip_q_wan { type ifname; elements = { "eth9", "pppoe-x" }; }`,
		"flags dynamic, timeout",
		"chain netgrip_q_input {",
		"udp dport { 53, 67, 123, 547 } return",
		"oifname != @netgrip_q_wan counter reject",
		"ip daddr @netgrip_q_private4 counter reject",
		"ip6 daddr @netgrip_q_private6 counter reject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	empty := renderQTable(qRuleSet{Mode: "nothing"})
	if strings.Contains(empty, "elements = {  }") || !strings.Contains(empty, "set netgrip_q_ok { type ether_addr; }") {
		t.Fatalf("empty sets:\n%s", empty)
	}
	if strings.Contains(empty, "oifname") {
		t.Fatal("nothing mode must not allow the WAN")
	}
}

func TestQRulesApprovedFirstAndPause(t *testing.T) {
	for _, rules := range [][]string{qInputRules(qRuleSet{Mode: "internet"}), qForwardRules(qRuleSet{Mode: "nothing"})} {
		if !strings.HasPrefix(rules[0], "ether saddr @netgrip_q_ok return") {
			t.Fatalf("approved devices must leave first: %v", rules)
		}
		if !strings.Contains(rules[len(rules)-1], "reject") {
			t.Fatalf("must end in a refusal: %v", rules)
		}
	}
	paused := qForwardRules(qRuleSet{Mode: "nothing", Paused: true})
	if paused[len(paused)-1] != "return" || strings.Contains(strings.Join(paused, "\n"), "reject") {
		t.Fatalf("pause off must enforce nothing: %v", paused)
	}
	if !strings.Contains(strings.Join(paused, "\n"), "update @netgrip_q_seen") {
		t.Fatal("pause off must still record devices")
	}
}

func TestRenderQRuntimeUpdateIsOneTransaction(t *testing.T) {
	out := renderQRuntimeUpdate(qRuleSet{Mode: "internet", Approved: []string{"02:00:00:00:00:01"}, Wan: []string{"eth9"}})
	for _, want := range []string{
		"flush chain inet fw4 netgrip_q_input", "flush chain inet fw4 netgrip_q_forward",
		"flush set inet fw4 netgrip_q_ok", "add element inet fw4 netgrip_q_ok { 02:00:00:00:00:01 }",
		`add element inet fw4 netgrip_q_wan { "eth9" }`, "table inet fw4 {",
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
	ops := qIncludeOps([]string{"netgrip_q_table", "netgrip_q_in_0"}, []string{"guests", "home"})
	for _, op := range ops {
		if err := executor.Validate(op); err != nil {
			t.Fatalf("op rejected by the executor: %v", err)
		}
	}
	joined := ""
	for _, op := range ops {
		joined += op.Kind + " " + strings.Join(op.Args, " ") + "\n"
	}
	for _, want := range []string{
		"uci_delete firewall.netgrip_q_table", "uci_delete firewall.netgrip_q_in_0",
		"uci_set firewall.netgrip_q_table.position table-prepend",
		"uci_set firewall.netgrip_q_in_0.chain input_guests",
		"uci_set firewall.netgrip_q_fw_1.chain forward_home",
		"uci_commit firewall", "initd firewall reload",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	// Removing everything adds nothing back.
	if strings.Contains(fmtOps(qIncludeOps([]string{"netgrip_q_table"}, nil)), "uci_set") {
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
	show := `firewall.netgrip_q_table=include
firewall.netgrip_q_table.path='/x'
firewall.netgrip_q_in_0=include
firewall.user_include=include
firewall.netgrip_qos=rule
firewall.@include[0]=include
`
	if got := strings.Join(qIncludeSections(show), ","); got != "netgrip_q_in_0,netgrip_q_table" {
		t.Fatalf("got %s", got)
	}
}

func TestParseNftSetElements(t *testing.T) {
	raw := `{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"netgrip_q_seen","elem":[
		"02:00:00:00:00:01",
		{"elem":{"val":"02:00:00:00:00:0A","timeout":3600,"expires":3500}}]}}]}`
	got, err := parseNftSetElements([]byte(raw))
	if err != nil || strings.Join(got, ",") != "02:00:00:00:00:01,02:00:00:00:00:0a" {
		t.Fatalf("got %v %v", got, err)
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
}

// ---- Flow tests with every system call faked ----

type qFake struct {
	t        *testing.T
	sections map[string]bool // owned include sections present in "UCI"
	applied  [][]executor.Op
	nft      []string
	checkErr error
	applyErr error
	verify   error
	seen     []string
	mu       sync.Mutex
	notified []string
	live     bool
}

func newQFake(t *testing.T) *qFake {
	t.Helper()
	dir := t.TempDir()
	f := &qFake{t: t, sections: map[string]bool{}}
	oldDir, oldState := quarantineDir, qStatePath
	quarantineDir = filepath.Join(dir, "q")
	qStatePath = filepath.Join(dir, "quarantine.json")
	t.Cleanup(func() { quarantineDir, qStatePath = oldDir, oldState })

	swap := func(restore func()) { t.Cleanup(restore) }
	oShow, oDump, oNft, oApply, oVerify, oReq, oApp, oIdent, oSeen, oNotify, oList, oChan :=
		uciShowFn, dumpInterfacesFn, nftRunFn, applyQIncludes, qVerifyLive, requesterMACFn, qApplicable, qIdentities, qSeenFn, qNotifyFn, listClientsFn, qChannelsFn
	swap(func() {
		uciShowFn, dumpInterfacesFn, nftRunFn, applyQIncludes, qVerifyLive, requesterMACFn, qApplicable, qIdentities, qSeenFn, qNotifyFn, listClientsFn, qChannelsFn =
			oShow, oDump, oNft, oApply, oVerify, oReq, oApp, oIdent, oSeen, oNotify, oList, oChan
	})

	uciShowFn = func(pkg string) string {
		if pkg == "dhcp" {
			return qTestDhcp
		}
		s := qTestFirewall
		for sec := range f.sections {
			s += "firewall." + sec + "=include\n"
		}
		return s
	}
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		if len(args) == 3 && args[1] == "get" && f.sections[strings.TrimPrefix(args[2], "firewall.")] {
			return []byte("include\n"), nil
		}
		return nil, errors.New("not found")
	})
	dumpInterfacesFn = func() []ubus.InterfaceState {
		return []ubus.InterfaceState{{Name: "uplink", Device: "eth9", L3Device: "pppoe-uplink"}}
	}
	nftRunFn = func(stdin string, args ...string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		if strings.HasPrefix(cmd, "-c ") {
			f.nft = append(f.nft, "check")
			return nil, f.checkErr
		}
		if strings.HasPrefix(cmd, "list chain") {
			if f.live {
				return []byte("chain"), nil
			}
			return nil, errors.New("no chain")
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
			sec := strings.TrimPrefix(op.Args[0], "firewall.")
			switch {
			case op.Kind == "uci_delete":
				delete(f.sections, sec)
			case op.Kind == "uci_set" && !strings.Contains(sec, "."):
				f.sections[sec] = true
			}
		}
		f.live = len(f.sections) > 0
		return nil
	}
	qVerifyLive = func([]string, string) error { return f.verify }
	requesterMACFn = func(ip string) string {
		if ip == "192.0.2.10" {
			return "02:00:00:00:00:10"
		}
		return ""
	}
	qApplicable = func() (bool, string) { return true, "" }
	qIdentities = func() qIdent {
		return qIdent{arp: map[string]string{"02:00:00:00:00:99": "192.0.2.99"}, leases: map[string]ubus.Lease{}, meta: map[string]ClientMeta{}}
	}
	qSeenFn = func() ([]string, error) { return f.seen, nil }
	qNotifyFn = func(_, _, plain string, _ bool) { f.mu.Lock(); f.notified = append(f.notified, plain); f.mu.Unlock() }
	listClientsFn = func(string) []Client { return nil }
	qChannelsFn = func() bool { return false }
	return f
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
	st := loadQState()
	if _, ok := st.Approved["02:00:00:00:00:10"]; !ok {
		t.Fatal("the panel user's device was not approved")
	}
	if st.Approved["02:00:00:00:00:20"].Name != "nas" {
		t.Fatalf("baseline: %+v", st.Approved)
	}
	table, err := os.ReadFile(qTableFile())
	if err != nil || !strings.Contains(string(table), "02:00:00:00:00:10") {
		t.Fatalf("include file: %v\n%s", err, table)
	}
	if !f.sections["netgrip_q_table"] || !f.sections["netgrip_q_in_0"] || !f.sections["netgrip_q_fw_0"] {
		t.Fatalf("sections: %v", f.sections)
	}
}

func TestQuarantineEnableRefusesWithoutRequester(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "198.51.100.7"); err == nil {
		t.Fatal("enabled without knowing the panel user's device")
	}
	if len(f.applied) != 0 || len(f.nft) != 0 {
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
	if _, err := os.Stat(qTableFile()); err == nil {
		t.Fatal("include file left behind")
	}
}

func TestQuarantineEnableRejectsBadInput(t *testing.T) {
	newQFake(t)
	for _, req := range []QEnableRequest{
		{Mode: "open", Zones: []string{"home"}},
		{Mode: "internet", Zones: []string{"up"}},
		{Mode: "internet", Zones: []string{"home"}, Approve: []QApproveItem{{MAC: "zz"}}},
	} {
		if _, err := QuarantineEnable(req, "192.0.2.10"); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
}

func TestQuarantineRevokeRefusesYourOwnDevice(t *testing.T) {
	newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}, Approve: []QApproveItem{{MAC: "02:00:00:00:00:20"}}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineRevoke("02:00:00:00:00:10", "192.0.2.10"); err == nil {
		t.Fatal("revoked the panel user's own device")
	}
	if _, err := QuarantineRevoke("02:00:00:00:00:20", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadQState().Approved["02:00:00:00:00:20"]; ok {
		t.Fatal("not revoked")
	}
}

func TestQuarantineDisableRemovesEverythingButKeepsApprovals(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home", "guests"}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineDisable(); err != nil {
		t.Fatal(err)
	}
	if len(f.sections) != 0 {
		t.Fatalf("sections left: %v", f.sections)
	}
	st := loadQState()
	if st.Enabled || len(st.Approved) == 0 {
		t.Fatalf("state: %+v", st)
	}
}

func TestQPollRecordsAndNotifiesOnce(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	qChannelsFn = func() bool { return true }
	f.seen = []string{"02:00:00:00:00:99", "02:00:00:00:00:10"}
	now := time.Now()
	qPoll(now)
	qPoll(now.Add(5 * time.Second))
	st := loadQState()
	if _, ok := st.Pending["02:00:00:00:00:10"]; ok {
		t.Fatal("an approved device was listed as pending")
	}
	p := st.Pending["02:00:00:00:00:99"]
	if p.IP != "192.0.2.99" || p.LastSeen <= p.FirstSeen-1 {
		t.Fatalf("pending: %+v", p)
	}
	qWaitFor(t, func() bool { return f.notifiedCount() >= 1 })
	time.Sleep(20 * time.Millisecond)
	if f.notifiedCount() != 1 {
		t.Fatalf("notified %d times", f.notifiedCount())
	}
}

func TestQPollLearningPauseApprovesAndEnds(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "nothing", Zones: []string{"home"}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantinePause(30, "learn"); err != nil {
		t.Fatal(err)
	}
	f.seen = []string{"02:00:00:00:00:31"}
	f.nft = nil
	qPoll(time.Now())
	st := loadQState()
	if st.Approved["02:00:00:00:00:31"].Via != "pause" {
		t.Fatalf("not learned: %+v", st.Approved)
	}
	if !strings.Contains(strings.Join(f.nft, "\n"), "02:00:00:00:00:31") {
		t.Fatal("the live set was not updated")
	}
	qChannelsFn = func() bool { return true }
	qPoll(time.Now().Add(31 * time.Minute))
	if loadQState().Pause.Until != 0 {
		t.Fatal("the pause did not end")
	}
	qWaitFor(t, func() bool { return f.notifiedCount() == 1 && strings.Contains(f.firstNotified(), "02:00:00:00:00:31") })
}

func TestQPauseOffSuspendsEnforcement(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "nothing", Zones: []string{"home"}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	f.nft = nil
	if _, err := QuarantinePause(10, "off"); err != nil {
		t.Fatal(err)
	}
	live := strings.Join(f.nft, "\n")
	if !strings.Contains(live, "flush chain") || strings.Contains(live, "reject") {
		t.Fatalf("pause off still enforces:\n%s", live)
	}
	table, _ := os.ReadFile(qTableFile())
	if strings.Contains(string(table), "reject") {
		t.Fatal("a reload during the pause would enforce again")
	}
	if _, err := QuarantinePause(10, "bogus"); err == nil {
		t.Fatal("bad pause kind accepted")
	}
}

func TestQPollNoticesARevert(t *testing.T) {
	f := newQFake(t)
	if _, err := QuarantineEnable(QEnableRequest{Mode: "internet", Zones: []string{"home"}}, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	f.sections = map[string]bool{} // the confirm window restored the old firewall
	qPoll(time.Now())
	if loadQState().Enabled {
		t.Fatal("still recorded as enabled after the sections vanished")
	}
}

func TestQPrunePending(t *testing.T) {
	now := time.Now()
	st := &qState{Pending: map[string]QPending{
		"02:00:00:00:00:01": {LastSeen: now.Add(-8 * 24 * time.Hour).Unix()},
		"02:00:00:00:00:02": {LastSeen: now.Unix()},
	}}
	if !qPrunePending(st, now) || len(st.Pending) != 1 {
		t.Fatalf("pending: %+v", st.Pending)
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

func (f *qFake) notifiedCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.notified) }

func (f *qFake) firstNotified() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.notified) == 0 {
		return ""
	}
	return f.notified[0]
}
