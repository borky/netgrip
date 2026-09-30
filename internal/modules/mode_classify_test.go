package modules

// FORK: tests for classifyMode.

import "testing"

func TestClassifyMode(t *testing.T) {
	for _, tc := range []struct {
		name                                          string
		wanInBridge, wanConfigured, dnsmasq, firewall bool
		want                                          string
	}{
		{"a gateway", false, true, true, true, "router"},
		{"a gateway with DNS behind AdGuard (dnsmasq moved, still on)", false, true, true, true, "router"},
		{"WAN port bridged into the LAN", true, true, false, false, "ap"},
		// The case that was shown as the main router: an uplink in its own
		// bridge with a DHCP client, holding the default route, and nothing
		// served or filtered.
		{"uplink in its own bridge, nothing served", false, true, false, false, "ap"},
		{"no uplink at all", false, false, true, true, "ap"},
		// Only one of the two off still routes (e.g. DHCP handed to another
		// server): not enough to call it an AP.
		{"firewall on, dnsmasq off", false, true, false, true, "router"},
		{"dnsmasq on, firewall off", false, true, true, false, "router"},
	} {
		if got := classifyMode(tc.wanInBridge, tc.wanConfigured, tc.dnsmasq, tc.firewall); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
