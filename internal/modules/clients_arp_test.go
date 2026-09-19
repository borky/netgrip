package modules

import (
	"testing"

	"github.com/gnacho/netgrip/internal/ubus"
)

const procArpSample = `IP address       HW type     Flags       HW address            Mask     Device
192.168.10.222   0x1         0x2         c8:ff:bf:0e:1e:26     *        br-lan
192.168.10.112   0x1         0x2         94:C9:60:DF:A5:6A     *        br-lan
192.168.10.50    0x1         0x0         00:00:00:00:00:00     *        br-lan
192.168.10.51    0x1         0x2         (incomplete)          *        br-lan
bad line with few fields
`

func TestParseProcArp(t *testing.T) {
	arp := parseProcArp(procArpSample)
	if len(arp) != 2 {
		t.Fatalf("want 2 resolved entries, got %d: %v", len(arp), arp)
	}
	if got := arp["c8:ff:bf:0e:1e:26"]; got != "192.168.10.222" {
		t.Errorf("wired static client: got ip %q", got)
	}
	if got := arp["94:c9:60:df:a5:6a"]; got != "192.168.10.112" {
		t.Errorf("uppercase mac should be lowercased: got %q", got)
	}
	if _, ok := arp["00:00:00:00:00:00"]; ok {
		t.Error("incomplete (0x0 flags) entry must be skipped")
	}
}

func TestParseProcArpEmpty(t *testing.T) {
	if arp := parseProcArp(""); len(arp) != 0 {
		t.Errorf("empty input should yield empty map, got %v", arp)
	}
}

func TestMergeArp(t *testing.T) {
	base := map[string]string{"aa:aa:aa:aa:aa:aa": "192.168.1.10"}
	extra := map[string]string{
		"aa:aa:aa:aa:aa:aa": "192.168.1.99", // conflict: base wins
		"bb:bb:bb:bb:bb:bb": "192.168.1.20",
	}
	merged := mergeArp(base, extra)
	if merged["aa:aa:aa:aa:aa:aa"] != "192.168.1.10" {
		t.Errorf("base entry must win on conflict, got %q", merged["aa:aa:aa:aa:aa:aa"])
	}
	if merged["bb:bb:bb:bb:bb:bb"] != "192.168.1.20" {
		t.Errorf("extra entry should fill gap, got %q", merged["bb:bb:bb:bb:bb:bb"])
	}
	if _, ok := base["bb:bb:bb:bb:bb:bb"]; ok {
		t.Error("mergeArp must not mutate its inputs")
	}
}

func TestFillIdentityArpFallback(t *testing.T) {
	var c Client
	fillIdentity(&c, "c8:ff:bf:0e:1e:26", "192.168.10.222", "", nil, map[string]string{
		"c8:ff:bf:0e:1e:26": "192.168.10.222",
	}, nil)
	if c.IP != "192.168.10.222" || c.IPSource != "arp" {
		t.Errorf("expected ARP-resolved ip, got %q (source %q)", c.IP, c.IPSource)
	}
	if !c.Self {
		t.Error("requester matching an ARP-resolved ip should be self")
	}
	if c.Name != "c8:ff:bf:0e:1e:26" {
		t.Errorf("name should fall back to mac, got %q", c.Name)
	}
}

func TestFillIdentityLeaseWins(t *testing.T) {
	leases := map[string]ubus.Lease{
		"94:c9:60:df:a5:6a": {MAC: "94:c9:60:df:a5:6a", IP: "192.168.10.112", Hostname: "tedeebridge"},
	}
	var c Client
	fillIdentity(&c, "94:c9:60:df:a5:6a", "", "local", leases, map[string]string{
		"94:c9:60:df:a5:6a": "192.168.1.999",
	}, nil)
	if c.IP != "192.168.10.112" || c.IPSource != "" {
		t.Errorf("lease ip must win over arp, got %q (source %q)", c.IP, c.IPSource)
	}
	if c.Name != "tedeebridge" {
		t.Errorf("lease hostname should be used, got %q", c.Name)
	}
}

func TestFillIdentityReservationName(t *testing.T) {
	// A device with a fixed address configured on the device itself never
	// asks for a lease, so the only name the router holds is the one pinned
	// in /etc/config/dhcp. Without reading it, such a client shows as a bare
	// MAC even though the router knows what it is.
	res := map[string]dhcpReservation{
		"02:00:00:00:00:01": {Name: "printer", IP: "192.0.2.10"},
	}
	var c Client
	fillIdentity(&c, "02:00:00:00:00:01", "", "", nil, map[string]string{
		"02:00:00:00:00:01": "192.0.2.10",
	}, res)
	if c.Name != "printer" || c.NameSource != "reservation" {
		t.Errorf("name should come from the reservation, got %q (source %q)", c.Name, c.NameSource)
	}
	if c.IP != "192.0.2.10" || c.IPSource != "arp" {
		t.Errorf("arp holds the live ip, got %q (source %q)", c.IP, c.IPSource)
	}
}

func TestFillIdentityReservationIPWhenSilent(t *testing.T) {
	// Not in ARP either (powered off, or nothing has talked to it yet): the
	// reservation is all there is.
	res := map[string]dhcpReservation{"02:00:00:00:00:02": {Name: "nas", IP: "192.0.2.20"}}
	var c Client
	fillIdentity(&c, "02:00:00:00:00:02", "", "", nil, nil, res)
	if c.IP != "192.0.2.20" || c.IPSource != "reservation" {
		t.Errorf("reservation ip should fill the gap, got %q (source %q)", c.IP, c.IPSource)
	}
}

func TestFillIdentityLeaseWinsOverReservation(t *testing.T) {
	// The lease is what the device answers to right now; the reservation is
	// only what the admin asked for.
	leases := map[string]ubus.Lease{
		"02:00:00:00:00:03": {MAC: "02:00:00:00:00:03", IP: "192.0.2.30", Hostname: "laptop"},
	}
	res := map[string]dhcpReservation{"02:00:00:00:00:03": {Name: "old-name", IP: "192.0.2.99"}}
	var c Client
	fillIdentity(&c, "02:00:00:00:00:03", "", "local", leases, nil, res)
	if c.Name != "laptop" || c.NameSource != "" {
		t.Errorf("lease hostname must win, got %q (source %q)", c.Name, c.NameSource)
	}
	if c.IP != "192.0.2.30" {
		t.Errorf("lease ip must win, got %q", c.IP)
	}
}
