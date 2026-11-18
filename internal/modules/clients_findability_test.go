package modules

import (
	"errors"
	"path/filepath"
	"sort"
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
	got := parseBridgeArp(content, "br-lan")
	if len(got) != 2 || got["02:00:00:00:00:01"] != "192.0.2.52" || got["02:00:00:00:00:02"] != "192.0.2.53" {
		t.Fatalf("bridge arp = %+v", got)
	}
}

func keepaliveTestSeams(t *testing.T, mode string, ages map[string]fdbAge, arp map[string]string) *[]string {
	t.Helper()
	sent := []string{}
	oldMode, oldAges, oldAgeing, oldArp, oldSend, oldWireless := probeModeFn, fdbAgesFn, bridgeAgeingFn, keepaliveArpFn, keepaliveSendFn, isWirelessPortFn
	probeModeFn = func() *ModeProbe { return &ModeProbe{Mode: mode} }
	fdbAgesFn = func(string) map[string]fdbAge { return ages }
	bridgeAgeingFn = func(string) time.Duration { return 300 * time.Second }
	keepaliveArpFn = func(string) map[string]string { return arp }
	keepaliveSendFn = func(ip string) { sent = append(sent, ip) }
	isWirelessPortFn = func(p string) bool { return strings.HasPrefix(p, "phy") }
	SetUciExecForTest(t, func(args ...string) ([]byte, error) { return nil, errors.New("no uci") })
	keepaliveMu.Lock()
	keepaliveLast = map[string]time.Time{}
	keepaliveMu.Unlock()
	t.Cleanup(func() {
		probeModeFn, fdbAgesFn, bridgeAgeingFn, keepaliveArpFn, keepaliveSendFn, isWirelessPortFn = oldMode, oldAges, oldAgeing, oldArp, oldSend, oldWireless
	})
	return &sent
}

func TestWiredKeepaliveProbesOnlyQuietWiredDevices(t *testing.T) {
	ages := map[string]fdbAge{
		"02:00:00:00:00:01": {port: "lan2", age: 250 * time.Second},     // quiet: probed
		"02:00:00:00:00:02": {port: "lan2", age: 30 * time.Second},      // active: left alone
		"02:00:00:00:00:03": {port: "phy1-ap0", age: 280 * time.Second}, // Wi-Fi: never
		"02:00:00:00:00:04": {port: "lan2", age: 260 * time.Second},     // no address: nothing to send to
	}
	arp := map[string]string{"02:00:00:00:00:01": "192.0.2.52", "02:00:00:00:00:02": "192.0.2.53", "02:00:00:00:00:03": "192.0.2.54"}
	sent := keepaliveTestSeams(t, "router", ages, arp)
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
	sent := keepaliveTestSeams(t, "ap", ages, map[string]string{"02:00:00:00:00:01": "192.0.2.52"})
	wiredKeepaliveTick(time.Now())
	if len(*sent) != 0 {
		t.Fatalf("an access point probed %v", *sent)
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
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:02"), now); len(got) != 0 {
		t.Fatalf("first run announced %v", got)
	}
	// A device that drops out and comes back is not new; the quiet one
	// seeded from the leases is not new either.
	m.newClients(cl("02:00:00:00:00:01"), now)
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:09"), now); len(got) != 0 {
		t.Fatalf("a returning device was announced: %v", got)
	}
	// A device never seen is new, once.
	if got := m.newClients(cl("02:00:00:00:00:01", "02:00:00:00:00:0A"), now); len(got) != 1 || got[0].MAC != "02:00:00:00:00:0A" {
		t.Fatalf("new device: %v", got)
	}
	if got := m.newClients(cl("02:00:00:00:00:0a"), now); len(got) != 0 {
		t.Fatalf("announced twice (case): %v", got)
	}
	// Kept across restarts.
	m2 := &Monitor{}
	if got := m2.newClients(cl("02:00:00:00:00:0a", "02:00:00:00:00:02"), now); len(got) != 0 {
		t.Fatalf("after a restart: %v", got)
	}
	if got := m2.newClients(cl("02:00:00:00:00:0b"), now); len(got) != 1 {
		t.Fatalf("after a restart a new device was not announced: %v", got)
	}
}

func TestKnownClientsCap(t *testing.T) {
	old := knownClientsPath
	knownClientsPath = filepath.Join(t.TempDir(), "known-clients.json")
	t.Cleanup(func() { knownClientsPath = old })
	known := map[string]int64{}
	for i := 0; i < knownClientsMax+5; i++ {
		mac := []byte("02:00:00:00:00:00")
		hex := "0123456789abcdef"
		mac[12], mac[13] = hex[(i>>12)&15], hex[(i>>8)&15]
		mac[15], mac[16] = hex[(i>>4)&15], hex[i&15]
		known[string(mac)] = int64(i)
	}
	if err := saveKnownClients(known); err != nil {
		t.Fatal(err)
	}
	got, ok := loadKnownClients()
	if !ok || len(got) != knownClientsMax {
		t.Fatalf("kept %d", len(got))
	}
	var firsts []int64
	for _, at := range got {
		firsts = append(firsts, at)
	}
	sort.Slice(firsts, func(i, j int) bool { return firsts[i] < firsts[j] })
	if firsts[0] != 5 {
		t.Fatalf("the oldest were not dropped first: %d", firsts[0])
	}
}
