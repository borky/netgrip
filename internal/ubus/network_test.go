package ubus

import (
	"encoding/json"
	"testing"
)

// Real ubus payload shape from a multi-WAN router: "isp" is the active
// PPPoE uplink, "wan" is a QMI failover interface that exists but is down
// (empty dns-server, no route).
const dumpRdsActiveWanFailover = `{
	"interface": [
		{
			"interface": "loopback",
			"up": true,
			"l3_device": "lo"
		},
		{
			"interface": "lan",
			"up": true,
			"l3_device": "br-lan",
			"ipv4-address": [
				{"address": "192.0.2.1", "mask": 24}
			]
		},
		{
			"interface": "wan",
			"up": false,
			"available": true,
			"dns-server": []
		},
		{
			"interface": "isp",
			"up": true,
			"uptime": 989739,
			"l3_device": "pppoe-isp",
			"proto": "pppoe",
			"ipv4-address": [
				{"address": "203.0.113.116", "mask": 32}
			],
			"route": [
				{"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1"}
			],
			"dns-server": ["198.51.100.53", "198.51.100.54"]
		}
	]
}`

func TestBuildWanStatusPicksActiveNonWanNamedInterface(t *testing.T) {
	status, err := buildWanStatus([]byte(dumpRdsActiveWanFailover))
	if err != nil {
		t.Fatalf("buildWanStatus: %v", err)
	}
	if !status.Present || !status.Up {
		t.Fatalf("status = %+v, want present+up", status)
	}
	if len(status.IPv4) != 1 || status.IPv4[0] != "203.0.113.116" {
		t.Fatalf("IPv4 = %v, want [203.0.113.116]", status.IPv4)
	}
	if status.Gateway != "203.0.113.1" {
		t.Fatalf("Gateway = %q, want 203.0.113.1", status.Gateway)
	}
	if len(status.DNS) != 2 || status.DNS[0] != "198.51.100.53" {
		t.Fatalf("DNS = %v, want [198.51.100.53 198.51.100.54]", status.DNS)
	}
}

// Single-WAN router, uplink temporarily down: must still report
// present+down, not "absent", even though nothing has a default route.
const dumpSingleWanDown = `{
	"interface": [
		{"interface": "loopback", "up": true},
		{"interface": "lan", "up": true, "l3_device": "br-lan"},
		{"interface": "wan", "up": false, "dns-server": []}
	]
}`

func TestBuildWanStatusFallsBackToNamedWanWhenNoneActive(t *testing.T) {
	status, err := buildWanStatus([]byte(dumpSingleWanDown))
	if err != nil {
		t.Fatalf("buildWanStatus: %v", err)
	}
	if !status.Present {
		t.Fatalf("status = %+v, want present", status)
	}
	if status.Up {
		t.Fatalf("status = %+v, want down", status)
	}
	if status.DNS == nil || len(status.DNS) != 0 {
		t.Fatalf("DNS = %v, want non-nil empty slice", status.DNS)
	}
}

// Real state observed on the LBR20: both interfaces report up (the QMI
// modem reconnected) but only "isp" actually carries the default route -
// "wan" is up with an empty route/dns-server, same shape as a link that's
// merely connected but not selected as the active gateway.
const dumpBothUpOnlyRdsRouted = `{
	"interface": [
		{"interface": "loopback", "up": true},
		{"interface": "lan", "up": true, "l3_device": "br-lan"},
		{
			"interface": "wan",
			"up": true,
			"proto": "qmi",
			"route": [],
			"dns-server": []
		},
		{
			"interface": "isp",
			"up": true,
			"proto": "pppoe",
			"ipv4-address": [{"address": "203.0.113.116", "mask": 32}],
			"route": [
				{"target": "0.0.0.0", "mask": 0, "nexthop": "198.51.100.1"}
			],
			"dns-server": ["198.51.100.53", "198.51.100.54"]
		}
	]
}`

func TestBuildWanStatusPrefersRoutedOverMerelyUpInterface(t *testing.T) {
	status, err := buildWanStatus([]byte(dumpBothUpOnlyRdsRouted))
	if err != nil {
		t.Fatalf("buildWanStatus: %v", err)
	}
	if !status.Present || !status.Up {
		t.Fatalf("status = %+v, want present+up", status)
	}
	if status.Gateway != "198.51.100.1" {
		t.Fatalf("Gateway = %q, want 198.51.100.1 (isp, not the merely-up wan)", status.Gateway)
	}
	if len(status.IPv4) != 1 || status.IPv4[0] != "203.0.113.116" {
		t.Fatalf("IPv4 = %v, want [203.0.113.116]", status.IPv4)
	}
}

func TestActiveWANInterfaceNamePrefersRoutedOverMerelyUpInterface(t *testing.T) {
	var dump interfaceDump
	if err := json.Unmarshal([]byte(dumpBothUpOnlyRdsRouted), &dump); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	iface, ok := pickWanInterface(dump.Interface)
	if !ok || iface.Interface != "isp" {
		t.Fatalf("pickWanInterface = %+v, ok=%v, want isp", iface, ok)
	}
}

// Real LBR20 config: PPPoE "isp" wired to physical port "lan1" carries the
// default route; "wan" is the QMI cellular modem (device is a /dev node,
// not an Ethernet port at all).
const dumpRdsOnLan1WanIsCellular = `{
	"interface": [
		{"interface": "loopback", "up": true, "device": "lo"},
		{"interface": "lan", "up": true, "device": "br-lan"},
		{"interface": "wan", "up": true, "proto": "qmi", "device": "/dev/cdc-wdm0", "route": [], "dns-server": []},
		{
			"interface": "isp",
			"up": true,
			"proto": "pppoe",
			"device": "lan1",
			"route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "198.51.100.1"}],
			"dns-server": ["198.51.100.53"]
		}
	]
}`

func TestActiveWANDevicePicksPhysicalPortOverCellular(t *testing.T) {
	dev := parseAndActiveWANDevice(t, dumpRdsOnLan1WanIsCellular)
	if dev != "lan1" {
		t.Fatalf("ActiveWANDevice-equivalent = %q, want lan1", dev)
	}
}

func parseAndActiveWANDevice(t *testing.T, raw string) string {
	t.Helper()
	var dump interfaceDump
	if err := json.Unmarshal([]byte(raw), &dump); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	iface, ok := pickWanInterface(dump.Interface)
	if !ok {
		t.Fatalf("pickWanInterface: no match")
	}
	return iface.Device
}

// Dumb AP: no wan-named interface and nothing with a default route.
const dumpApOnly = `{
	"interface": [
		{"interface": "loopback", "up": true},
		{"interface": "lan", "up": true, "l3_device": "br-lan"}
	]
}`

func TestBuildWanStatusAbsentOnAP(t *testing.T) {
	status, err := buildWanStatus([]byte(dumpApOnly))
	if err != nil {
		t.Fatalf("buildWanStatus: %v", err)
	}
	if status.Present {
		t.Fatalf("status = %+v, want absent", status)
	}
}
