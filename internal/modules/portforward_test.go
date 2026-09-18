package modules

import "testing"

// The factory config is how a stock rule is recognised, so that the rules
// every OpenWrt ships with (DHCP renew, ISAKMP, the ICMP ones) do not bury
// the one rule somebody actually opened. Read from /rom, never hardcoded.
func TestParseStockNames(t *testing.T) {
	const cfg = `
config defaults
	option input 'REJECT'

config zone
	option name		lan
	option input 'ACCEPT'

config rule
	option name		Allow-DHCP-Renew
	option src		wan
	option proto		udp
	option dest_port	68
	option target		ACCEPT

config rule
	option name 'Allow-ISAKMP'
	option dest_port	500
`
	got := parseStockNames(cfg)
	for _, want := range []string{"lan", "Allow-DHCP-Renew", "Allow-ISAKMP"} {
		if !got[want] {
			t.Errorf("%q should be recognised as stock: %v", want, got)
		}
	}
	if got["Allow-Something-Else"] {
		t.Error("a rule that is not in the factory config is not stock")
	}
	if len(got) != 3 {
		t.Errorf("names: %v", got)
	}
}

// No /rom (a container, an image without the read-only base): nothing is
// treated as stock, which errs towards showing a rule rather than hiding it.
func TestParseStockNamesOnNothing(t *testing.T) {
	if got := parseStockNames(""); len(got) != 0 {
		t.Errorf("names: %v", got)
	}
}
