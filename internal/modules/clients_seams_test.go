package modules

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
)

// Phase 3 of plans/backend-seam-clients: ListClients runs end to end with
// every device read faked - no ubus, no uci, no ssh, no sysfs, no /etc.
// This is the dress rehearsal for the phase 4 handler test.
func TestListClientsWithSeams(t *testing.T) {
	dir := t.TempDir()
	leaseFile := filepath.Join(dir, "dhcp.leases")
	// <expiry> <mac> <ip> <hostname> <client-id>
	if err := os.WriteFile(leaseFile, []byte("0 aa:bb:cc:00:00:01 192.168.1.50 portatil 01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arpFile := filepath.Join(dir, "arp")
	if err := os.WriteFile(arpFile, []byte(
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"192.168.1.50     0x1         0x2         aa:bb:cc:00:00:01     *        br-lan\n"+
			"192.168.1.60     0x1         0x2         aa:bb:cc:00:00:02     *        br-lan\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &fakeClientsBackend{radios: []ubus.WirelessRadio{{
		Name: "radio0", Band: "5g", Up: true,
		Interfaces: []ubus.WirelessInterface{{
			Ifname: "phy0-ap0",
			Clients: []ubus.WirelessClient{
				{MAC: "AA:BB:CC:00:00:01", Signal: -50, RxBytes: 100, TxBytes: 200},
			},
		}},
	}}}
	ubus.SetBackendForTest(t, fake)

	calls := 0
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		calls++
		if len(args) == 2 && args[0] == "show" && args[1] == "dhcp" {
			return []byte("dhcp.host1=host\ndhcp.host1.name='reservado'\ndhcp.host1.mac='aa:bb:cc:00:00:02'\ndhcp.host1.ip='192.168.1.60'\n"), nil
		}
		if len(args) == 2 && args[0] == "show" && args[1] == "wireless" {
			return []byte("wireless.default_radio0=wifi-device\n"), nil
		}
		return nil, errors.New("unexpected uci call")
	})
	SetGatewaySSHForTest(t, func(command string) (string, error) {
		return "", errors.New("no gateway in test")
	})
	InvalidateKey("ucishow|dhcp")
	InvalidateKey("ucishow|wireless")

	SetClientsSeamsForTest(t, ClientsSeams{
		LeaseFile:           leaseFile,
		ArpFile:             arpFile,
		BridgeFdb:           func() map[string][]string { return map[string][]string{"lan1": {"AA:BB:CC:00:00:02"}} },
		ServiceEnabled:      func(name string) bool { return name == "firewall" },
		ProbeMode:           func() *ModeProbe { return &ModeProbe{Mode: "router"} },
		RouterClock:         func() (time.Time, bool) { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), true },
		ParentalPath:        filepath.Join(dir, "parental.json"),
		ParentalAppliedPath: filepath.Join(dir, "parental-applied.json"),
		CableBlocked:        func() map[string]bool { return map[string]bool{} },
		ClientMetaPath:      filepath.Join(dir, "clients.json"),
		QuotaConfigFile:     filepath.Join(dir, "quota.json"),
		QuotaStateFile:      filepath.Join(dir, "quota-state.json"),
	})

	clients := ListClients("192.168.1.50")
	if len(clients) != 2 {
		t.Fatalf("ListClients returned %d clients, want 2: %+v", len(clients), clients)
	}

	byMAC := map[string]Client{}
	for _, c := range clients {
		byMAC[c.MAC] = c
	}

	wifi, ok := byMAC["aa:bb:cc:00:00:01"]
	if !ok {
		t.Fatalf("wifi client missing: %+v", byMAC)
	}
	if wifi.Type != "wifi5" || wifi.Name != "portatil" || wifi.IP != "192.168.1.50" || wifi.Signal != -50 {
		t.Errorf("wifi client = %+v", wifi)
	}
	if !wifi.Self {
		t.Errorf("wifi client should be flagged self (requester 192.168.1.50)")
	}
	if !wifi.Blockable {
		t.Errorf("wifi client should be blockable")
	}

	cable, ok := byMAC["aa:bb:cc:00:00:02"]
	if !ok {
		t.Fatalf("wired client missing: %+v", byMAC)
	}
	if cable.Type != "cable" || cable.Iface != "lan1" {
		t.Errorf("wired client type/iface = %s/%s, want cable/lan1", cable.Type, cable.Iface)
	}
	if cable.Name != "reservado" || !cable.Reserved {
		t.Errorf("wired client should carry the reservation identity: %+v", cable)
	}
	if cable.Self {
		t.Errorf("wired client must not be self")
	}
	if cable.Blockable != true {
		t.Errorf("wired client blockable = %v, want true (firewall on)", cable.Blockable)
	}
}

type fakeClientsBackend struct {
	calls  int
	radios []ubus.WirelessRadio
}

func (f *fakeClientsBackend) SystemInfo() (*ubus.SystemInfo, error) { return nil, nil }

func (f *fakeClientsBackend) WanStatus() (*ubus.WanStatus, error) { return nil, nil }

func (f *fakeClientsBackend) WirelessStatus() ([]ubus.WirelessRadio, error) {
	f.calls++
	return f.radios, nil
}

func (f *fakeClientsBackend) SystemBoard() (json.RawMessage, error) { return nil, nil }

// A station the quarantine's Wi-Fi layer moved to a per-VLAN interface
// (learned on a bridge port such as <ifname>-ngq) is one Wi-Fi row, not also
// a cable one; a device without a hostname takes the name it was approved
// with; a name set for the client still wins.
func TestListClientsWifiVlanPortAndApprovedName(t *testing.T) {
	newQFake(t)
	qMu.Lock()
	st := loadQState()
	st.Approved["02:00:00:00:00:21"] = QApproved{Name: "Printer", Via: "manual"}
	st.Approved["02:00:00:00:00:22"] = QApproved{Name: "Approved name", Via: "manual"}
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
	qMu.Unlock()

	dir := t.TempDir()
	leaseFile := filepath.Join(dir, "dhcp.leases")
	if err := os.WriteFile(leaseFile, []byte("0 02:00:00:00:00:21 192.0.2.21 * 01:02\n0 02:00:00:00:00:22 192.0.2.22 laptop 01:03\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(meta, []byte(`{"02:00:00:00:00:22":{"name":"Desk"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ubus.SetBackendForTest(t, &fakeClientsBackend{radios: []ubus.WirelessRadio{{
		Name: "radio0", Band: "2g", Up: true,
		Interfaces: []ubus.WirelessInterface{{
			Ifname:  "wl0",
			Clients: []ubus.WirelessClient{{MAC: "02:00:00:00:00:21", Signal: -60}},
		}},
	}}})
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "show" {
			return []byte(""), nil
		}
		return nil, errors.New("unexpected uci call")
	})
	SetGatewaySSHForTest(t, func(string) (string, error) { return "", errors.New("no gateway in test") })
	InvalidateKey("ucishow|dhcp")
	InvalidateKey("ucishow|wireless")
	SetClientsSeamsForTest(t, ClientsSeams{
		LeaseFile: leaseFile,
		ArpFile:   filepath.Join(dir, "arp"),
		BridgeFdb: func() map[string][]string {
			return map[string][]string{"wl0-vlan": {"02:00:00:00:00:21"}, "eth1": {"02:00:00:00:00:22"}}
		},
		WirelessPort:        func(p string) bool { return p == "wl0-vlan" },
		ServiceEnabled:      func(string) bool { return true },
		ProbeMode:           func() *ModeProbe { return &ModeProbe{Mode: "router"} },
		RouterClock:         func() (time.Time, bool) { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), true },
		ParentalPath:        filepath.Join(dir, "parental.json"),
		ParentalAppliedPath: filepath.Join(dir, "parental-applied.json"),
		CableBlocked:        func() map[string]bool { return map[string]bool{} },
		ClientMetaPath:      meta,
		QuotaConfigFile:     filepath.Join(dir, "quota.json"),
		QuotaStateFile:      filepath.Join(dir, "quota-state.json"),
	})

	clients := ListClients("")
	if len(clients) != 2 {
		t.Fatalf("%d rows, want 2: %+v", len(clients), clients)
	}
	byMAC := map[string]Client{}
	for _, c := range clients {
		byMAC[c.MAC] = c
	}
	if c := byMAC["02:00:00:00:00:21"]; c.Type != "wifi24" || c.Name != "Printer" || c.NameSource != "quarantine" {
		t.Fatalf("the Wi-Fi station: %+v", c)
	}
	if c := byMAC["02:00:00:00:00:22"]; c.Type != "cable" || c.Name != "Desk" || c.NameSource != "" {
		t.Fatalf("the wired client: %+v", c)
	}
}
