package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
)

func TestNetworkForIP(t *testing.T) {
	subnets := []ubus.Subnet{
		{Interface: "lan", Address: "192.0.2.1", Mask: 24},
		{Interface: "iot", Address: "198.51.100.1", Mask: 24},
		{Interface: "lan_small", Address: "192.0.2.129", Mask: 25}, // more specific
		{Interface: "wan", Address: "203.0.113.7", Mask: 32},       // an uplink's own address
	}
	cases := map[string]string{
		"192.0.2.10":   "lan",
		"192.0.2.200":  "lan_small",
		"198.51.100.9": "iot",
		"203.0.113.7":  "",
		"203.0.113.8":  "",
		"":             "",
		"not-an-ip":    "",
		"2001:db8::1":  "",
	}
	for ip, want := range cases {
		if got := networkForIP(ip, subnets); got != want {
			t.Errorf("networkForIP(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestParseSubnetsSkipsDownInterfaces(t *testing.T) {
	raw := []byte(`{"interface":[
		{"interface":"lan","up":true,"ipv4-address":[{"address":"192.0.2.1","mask":24}]},
		{"interface":"guest","up":false,"ipv4-address":[{"address":"198.51.100.1","mask":24}]},
		{"interface":"wan","up":true,"ipv4-address":[]}]}`)
	got, err := ubus.ParseSubnets(raw)
	if err != nil || len(got) != 1 || got[0].Interface != "lan" || got[0].Mask != 24 {
		t.Fatalf("ParseSubnets = %+v, %v", got, err)
	}
}

func TestParseFdbAges(t *testing.T) {
	out := "port no\tmac addr\t\tis local?\tageing timer\n" +
		"  1\t02:00:00:00:00:01\tno\t\t 211.85\n" +
		"  1\t02:00:00:00:00:01\tno\t\t  12.00\n" + // same MAC, another VLAN: the youngest wins
		"  2\t02:00:00:00:00:02\tno\t\t   0.44\n" +
		"  1\t02:00:00:00:00:aa\tyes\t\t   0.00\n" + // local
		"  9\t02:00:00:00:00:03\tno\t\t   1.00\n" // unknown port
	ages := parseFdbAges(out, map[int]string{1: "lan2", 2: "phy1-ap0"})
	if len(ages) != 2 {
		t.Fatalf("ages = %+v", ages)
	}
	if a := ages["02:00:00:00:00:01"]; a.port != "lan2" || a.age != 12*time.Second {
		t.Errorf("youngest entry not kept: %+v", a)
	}
}

func TestParseBridgeArp(t *testing.T) {
	content := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.0.2.52       0x1         0x2         02:00:00:00:00:01     *        br-lan.10\n" +
		"192.0.2.53       0x1         0x2         02:00:00:00:00:02     *        br-lan\n" +
		"203.0.113.1      0x1         0x2         02:00:00:00:00:03     *        pppoe-wan\n" +
		"192.0.2.54       0x1         0x0         00:00:00:00:00:00     *        br-lan\n" +
		"198.51.100.5     0x1         0x2         02:00:00:00:00:04     *        br-lanx\n"
	// The bridge and the device stacked on it, whatever its name.
	got := parseBridgeArp(content+"192.0.2.60       0x1         0x2         02:00:00:00:00:01     *        br-lan.10\n",
		map[string]bool{"br-lan": true, "br-lan.10": true})
	if len(got) != 2 || len(got["02:00:00:00:00:01"]) != 2 || got["02:00:00:00:00:02"][0].ip != "192.0.2.53" {
		t.Fatalf("bridge arp = %+v", got)
	}
}

func TestOnDeviceSubnet(t *testing.T) {
	subnets := []ubus.Subnet{
		{Interface: "lan", Device: "br-lan.10", Address: "192.0.2.1", Mask: 24},
		{Interface: "wan", Device: "pppoe-wan", Address: "203.0.113.7", Mask: 32},
	}
	cases := []struct {
		ip, dev string
		want    bool
	}{
		{"192.0.2.52", "br-lan.10", true},
		{"192.0.2.52", "br-lan.11", false},  // another device's subnet
		{"169.254.3.4", "br-lan.10", false}, // off-subnet: would follow the default route
		{"203.0.113.7", "pppoe-wan", false}, // a host route
		{"2001:db8::1", "br-lan.10", false},
	}
	for _, c := range cases {
		if got := onDeviceSubnet(c.ip, c.dev, subnets); got != c.want {
			t.Errorf("onDeviceSubnet(%s, %s) = %v", c.ip, c.dev, got)
		}
	}
}

func keepaliveTestSeams(t *testing.T, mode string, ages map[string]fdbAge, arp map[string]string) (*[]string, *time.Duration) {
	t.Helper()
	sent := []string{}
	ageing := 300 * time.Second
	oldMode, oldBridge, oldAges, oldAgeing, oldArp, oldSend, oldWireless, oldSubnets := keepaliveModeFn, keepaliveBridgeFn, fdbAgesFn, bridgeAgeingFn, keepaliveArpFn, keepaliveSendFn, isWirelessPortFn, clientSubnetsFn
	keepaliveModeFn = func() string { return mode }
	keepaliveBridgeFn = func() string { return "br-lan" }
	fdbAgesFn = func(string) map[string]fdbAge { return ages }
	bridgeAgeingFn = func(string) time.Duration { return ageing }
	keepaliveArpFn = func(string) map[string][]arpRow {
		out := map[string][]arpRow{}
		for mac, ip := range arp {
			out[mac] = []arpRow{{ip: ip, dev: "br-lan.10"}}
		}
		return out
	}
	keepaliveSendFn = func(ip string) { sent = append(sent, ip) }
	isWirelessPortFn = func(p string) bool { return strings.HasPrefix(p, "phy") }
	clientSubnetsFn = func() []ubus.Subnet {
		return []ubus.Subnet{{Interface: "lan", Device: "br-lan.10", Address: "192.0.2.1", Mask: 24}}
	}
	keepaliveMu.Lock()
	keepaliveLast = map[string]time.Time{}
	keepaliveMu.Unlock()
	t.Cleanup(func() {
		keepaliveModeFn, keepaliveBridgeFn, fdbAgesFn, bridgeAgeingFn, keepaliveArpFn, keepaliveSendFn, isWirelessPortFn, clientSubnetsFn = oldMode, oldBridge, oldAges, oldAgeing, oldArp, oldSend, oldWireless, oldSubnets
	})
	return &sent, &ageing
}

func TestWiredKeepaliveProbesOnlyQuietWiredDevices(t *testing.T) {
	ages := map[string]fdbAge{
		"02:00:00:00:00:01": {port: "lan2", age: 250 * time.Second},     // quiet: probed
		"02:00:00:00:00:02": {port: "lan2", age: 30 * time.Second},      // active: left alone
		"02:00:00:00:00:03": {port: "phy1-ap0", age: 280 * time.Second}, // Wi-Fi: never
		"02:00:00:00:00:04": {port: "lan2", age: 260 * time.Second},     // no address: nothing to send to
	}
	arp := map[string]string{"02:00:00:00:00:01": "192.0.2.52", "02:00:00:00:00:02": "192.0.2.53", "02:00:00:00:00:03": "192.0.2.54"}
	sent, _ := keepaliveTestSeams(t, "router", ages, arp)
	now := time.Unix(1_700_000_000, 0)
	wiredKeepaliveTick(now)
	if strings.Join(*sent, ",") != "192.0.2.52" {
		t.Fatalf("sent to %v", *sent)
	}
	// Not again within the minimum gap; again after it.
	wiredKeepaliveTick(now.Add(20 * time.Second))
	if len(*sent) != 1 {
		t.Fatalf("probed twice within the gap: %v", *sent)
	}
	wiredKeepaliveTick(now.Add(time.Minute))
	if len(*sent) != 2 {
		t.Fatalf("not probed again after the gap: %v", *sent)
	}
}

func TestWiredKeepaliveSendsNothingOnAnAccessPoint(t *testing.T) {
	ages := map[string]fdbAge{"02:00:00:00:00:01": {port: "lan2", age: 290 * time.Second}}
	sent, _ := keepaliveTestSeams(t, "ap", ages, map[string]string{"02:00:00:00:00:01": "192.0.2.52"})
	wiredKeepaliveTick(time.Now())
	if len(*sent) != 0 {
		t.Fatalf("an access point probed %v", *sent)
	}
}

func TestWiredKeepaliveSkipsOffSubnetAndShortAgeing(t *testing.T) {
	ages := map[string]fdbAge{"02:00:00:00:00:01": {port: "lan2", age: 250 * time.Second}}
	// An address outside the device's subnet is never probed.
	sent, ageing := keepaliveTestSeams(t, "router", ages, map[string]string{"02:00:00:00:00:01": "169.254.3.4"})
	wiredKeepaliveTick(time.Now())
	if len(*sent) != 0 {
		t.Fatalf("an off-subnet address was probed: %v", *sent)
	}
	// An ageing time too short to probe in time: nothing is done.
	keepaliveArpFn = func(string) map[string][]arpRow {
		return map[string][]arpRow{"02:00:00:00:00:01": {{ip: "192.0.2.52", dev: "br-lan.10"}}}
	}
	*ageing = 90 * time.Second
	ages["02:00:00:00:00:01"] = fdbAge{port: "lan2", age: 80 * time.Second}
	wiredKeepaliveTick(time.Now())
	if len(*sent) != 0 {
		t.Fatalf("probed with a 90 s ageing time: %v", *sent)
	}
}

func TestKnownClientsNewOnlyOnce(t *testing.T) {
	old := knownClientsPath
	knownClientsPath = filepath.Join(t.TempDir(), "known-clients.json")
	oldSeed := knownSeedMACsFn
	knownSeedMACsFn = func() []string { return []string{"02:00:00:00:00:09"} } // quiet now, has a lease
	t.Cleanup(func() { knownClientsPath, knownSeedMACsFn = old, oldSeed })
	now := time.Unix(1_700_000_000, 0)
	cl := func(macs ...string) []Client {
		var out []Client
		for _, m := range macs {
			out = append(out, Client{MAC: m})
		}
		return out
	}
	m := &Monitor{}
	// First run: everything known is recorded, nothing announced.
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:02"), now, false); len(got) != 0 {
		t.Fatalf("first run announced %v", got)
	}
	// A device that drops out and comes back is not new; the quiet one
	// seeded from the leases is not new either.
	m.newClients(cl("02:00:00:00:00:01"), now, false)
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:09"), now, false); len(got) != 0 {
		t.Fatalf("a returning device was announced: %v", got)
	}
	// A device never seen is new, once.
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:0A"), now, false); len(got) != 1 || got[0].MAC != "02:00:00:00:00:0A" {
		t.Fatalf("new device: %v", got)
	}
	if got := m.newClients(cl("02:00:00:00:00:0a"), now, false); len(got) != 0 {
		t.Fatalf("announced twice (case): %v", got)
	}
	// Kept across restarts.
	m2 := &Monitor{}
	if got := m2.newClients(cl("02:00:00:00:00:0a", "02:00:00:00:00:02"), now, false); len(got) != 0 {
		t.Fatalf("after a restart: %v", got)
	}
	if got := m2.newClients(cl("02:00:00:00:00:0b"), now, false); len(got) != 1 {
		t.Fatalf("after a restart a new device was not announced: %v", got)
	}
}

func TestKnownClientsCapDropsLongestUnseenNeverPresent(t *testing.T) {
	old := knownClientsPath
	knownClientsPath = filepath.Join(t.TempDir(), "known-clients.json")
	t.Cleanup(func() { knownClientsPath = old })
	mac := func(i int) string {
		b := []byte("02:00:00:00:00:00")
		hex := "0123456789abcdef"
		b[12], b[13] = hex[(i>>12)&15], hex[(i>>8)&15]
		b[15], b[16] = hex[(i>>4)&15], hex[i&15]
		return string(b)
	}
	known, last := map[string]int64{}, map[string]int64{}
	for i := 0; i < knownClientsMax+5; i++ {
		known[mac(i)] = 0           // all first seen together (the seed)
		last[mac(i)] = int64(i + 1) // seen at different times since
	}
	present := map[string]bool{mac(0): true, mac(1): true} // longest unseen, but online now
	if err := saveKnownClients(known, last, present); err != nil {
		t.Fatal(err)
	}
	got, gotLast, ok := loadKnownClients()
	if !ok || len(got) != knownClientsMax {
		t.Fatalf("kept %d", len(got))
	}
	for _, i := range []int{0, 1} {
		if _, ok := got[mac(i)]; !ok {
			t.Errorf("an online device was dropped: %s", mac(i))
		}
	}
	for _, i := range []int{2, 3, 4, 5, 6} {
		if _, ok := got[mac(i)]; ok {
			t.Errorf("a long-unseen device was kept: %s", mac(i))
		}
	}
	if gotLast[mac(7)] != 8 {
		t.Errorf("last seen not kept: %d", gotLast[mac(7)])
	}
}

func TestKnownClientsSilentResync(t *testing.T) {
	old := knownClientsPath
	knownClientsPath = filepath.Join(t.TempDir(), "known-clients.json")
	oldSeed := knownSeedMACsFn
	knownSeedMACsFn = func() []string { return nil }
	t.Cleanup(func() { knownClientsPath, knownSeedMACsFn = old, oldSeed })
	now := time.Unix(1_700_000_000, 0)
	m := &Monitor{}
	m.newClients([]Client{{MAC: "02:00:00:00:00:01"}}, now, false)
	// Notifications were off meanwhile: what joined is recorded, not announced.
	if got := m.newClients([]Client{{MAC: "02:00:00:00:00:01"}, {MAC: "02:00:00:00:00:02"}}, now, true); len(got) != 0 {
		t.Fatalf("resync announced %v", got)
	}
	if got := m.newClients([]Client{{MAC: "02:00:00:00:00:02"}, {MAC: "02:00:00:00:00:03"}}, now, false); len(got) != 1 || got[0].MAC != "02:00:00:00:00:03" {
		t.Fatalf("after resync: %v", got)
	}
}

func TestParseSubnetsKeepsTheDevice(t *testing.T) {
	raw := []byte(`{"interface":[{"interface":"lan","up":true,"l3_device":"br-lan.10","ipv4-address":[{"address":"192.0.2.1","mask":24}]}]}`)
	got, err := ubus.ParseSubnets(raw)
	if err != nil || len(got) != 1 || got[0].Device != "br-lan.10" {
		t.Fatalf("ParseSubnets = %+v, %v", got, err)
	}
}

func TestBridgeDevicesFromSysfs(t *testing.T) {
	dir := t.TempDir()
	old := sysNetDir
	sysNetDir = dir
	t.Cleanup(func() { sysNetDir = old })
	for _, n := range []string{"br0/upper_vlan-iot", "br0/upper_br0.20", "br0/lower_lan1", "br0/bridge"} {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := bridgeDevices("br0")
	if len(got) != 3 || !got["br0"] || !got["vlan-iot"] || !got["br0.20"] {
		t.Fatalf("bridge devices = %v", got)
	}
}

func TestKnownClientsLoadsAFileWithoutLastSeen(t *testing.T) {
	old := knownClientsPath
	knownClientsPath = filepath.Join(t.TempDir(), "known-clients.json")
	t.Cleanup(func() { knownClientsPath = old })
	if err := os.WriteFile(knownClientsPath, []byte(`{"first_seen":{"02:00:00:00:00:01":100,"bogus":5}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	first, last, ok := loadKnownClients()
	if !ok || len(first) != 1 || last["02:00:00:00:00:01"] != 100 {
		t.Fatalf("first=%v last=%v ok=%v", first, last, ok)
	}
}

func TestMonitorStartsWithoutResync(t *testing.T) {
	// A restart is not a resync: the saved list already says what is known,
	// and a device that joined meanwhile must still be announced.
	StopMonitor()
	StartMonitor()
	t.Cleanup(StopMonitor)
	if monitorInstance.resync {
		t.Fatal("the monitor starts silent")
	}
}
