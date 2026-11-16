package modules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
)

func TestDevHostname(t *testing.T) {
	for in, want := range map[string]string{
		"X1C":                   "X1C",
		"Living room TV":        "Living-room-TV",
		"  --Ørsted  lamp!":     "rsted-lamp",
		"*":                     "",
		"":                      "",
		strings.Repeat("a", 70): strings.Repeat("a", 63),
		// What dnsmasq reads as something other than a name.
		"2024": "", "12h": "", "7D": "", "ignore": "", "Infinite": "",
		"12h lamp": "12h-lamp", "x2024": "x2024",
	} {
		if got := devHostname(in); got != want {
			t.Errorf("devHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeMAC(t *testing.T) {
	for in, want := range map[string]bool{
		"02:00:00:00:00:21": true, "02-00-00-00-00-21": true, "020000000021": true,
		"X1C": false, "decade": false, "02:00:00:00:00": false,
	} {
		if looksLikeMAC(in) != want {
			t.Errorf("looksLikeMAC(%q) != %v", in, want)
		}
	}
}

func devHost(name, mac string, extra ...string) uciSection {
	o := map[string][]string{}
	if mac != "" {
		o["mac"] = []string{mac}
	}
	if name != "" {
		o["name"] = []string{name}
	}
	for i := 0; i+1 < len(extra); i += 2 {
		o[extra[i]] = []string{extra[i+1]}
	}
	return uciSection{Type: "host", Options: o}
}

func opsText(ops []executor.Op) string {
	var b strings.Builder
	for _, o := range ops {
		b.WriteString(o.Kind + " " + strings.Join(o.Args, " ") + "\n")
	}
	return b.String()
}

// Which devices get a name, and which are left alone and why.
func TestDevNamesPlan(t *testing.T) {
	dhcp := map[string]uciSection{
		"lan":                          {Type: "dhcp", Options: map[string][]string{"interface": {"lan"}}},
		"mine":                         devHost("nas", "02:00:00:00:00:05"),
		"noname":                       devHost("", "02:00:00:00:00:06"),
		"netgrip_devname_020000000007": devHost("old-name", "02:00:00:00:00:07", devNamedOpt, "1"),
		"netgrip_host_020000000008":    devHost("", "02:00:00:00:00:08", "ip", "192.0.2.8"),
		"netgrip_host_020000000009":    devHost("set-by-hand", "02:00:00:00:00:09", "ip", "192.0.2.9"),
		"netgrip_devname_02000000000a": devHost("same", "02:00:00:00:00:0a", devNamedOpt, "1"),
		"netgrip_host_02000000000c":    devHost("Desk-PC", "02:00:00:00:00:0c", "ip", "192.0.2.12", devNamedOpt, "1"),
		"netgrip_devname_02000000000d": devHost("moved", "02:00:00:00:00:99", devNamedOpt, "1"), // its MAC edited by hand
		"printer_dns":                  {Type: "domain", Options: map[string][]string{"name": {"printer"}, "ip": {"192.0.2.50"}}},
		"two":                          devHost("multi", "02:00:00:00:00:0f 02:00:00:00:00:10"),
	}
	leases := map[string]string{
		"02:00:00:00:00:01": "*",
		"02:00:00:00:00:02": "phone",
		"02:00:00:00:00:04": "*",
		"02:00:00:00:00:08": "*",
		"02:00:00:00:00:0d": "*",
		"02:00:00:00:00:0e": "*",
		"02:00:00:00:00:10": "*",
	}
	want := map[string]string{
		"02:00:00:00:00:01": "X1C",       // no hostname: named
		"02:00:00:00:00:02": "Pixel",     // names itself
		"02:00:00:00:00:03": "Offline",   // no lease: waits for one
		"02:00:00:00:00:04": "nas",       // the name is taken by another device
		"02:00:00:00:00:05": "Something", // the user's own entry with a name
		"02:00:00:00:00:06": "Something", // the user's own entry without one
		"02:00:00:00:00:07": "New-name",  // NetGrip's entry: renamed
		"02:00:00:00:00:08": "Desk-PC2",  // NetGrip's reservation: gets the name
		"02:00:00:00:00:09": "Desk-PC3",  // NetGrip's reservation named by hand
		"02:00:00:00:00:0a": "same",      // already so
		"02:00:00:00:00:0b": "",          // nothing usable
		"02:00:00:00:00:0c": "Office-PC", // NetGrip named its reservation: renamed
		"02:00:00:00:00:0d": "Moved",     // NetGrip's entry edited by hand
		"02:00:00:00:00:0e": "PRINTER",   // a local DNS record has it
		"02:00:00:00:00:10": "Second",    // in a multi-MAC entry of the user's
	}
	ops, named, skipped, noLease := devNamesPlan(dhcp, leases, want)
	wantNamed := map[string]string{"02:00:00:00:00:01": "X1C", "02:00:00:00:00:07": "New-name",
		"02:00:00:00:00:08": "Desk-PC2", "02:00:00:00:00:0c": "Office-PC"}
	if len(named) != len(wantNamed) {
		t.Fatalf("named %v, skipped %v", named, skipped)
	}
	for m, h := range wantNamed {
		if named[m] != h {
			t.Fatalf("%s named %q, want %q (all: %v)", m, named[m], h, named)
		}
	}
	for _, m := range []string{"02:00:00:00:00:02", "02:00:00:00:00:03", "02:00:00:00:00:04", "02:00:00:00:00:05",
		"02:00:00:00:00:06", "02:00:00:00:00:09", "02:00:00:00:00:0b", "02:00:00:00:00:0d", "02:00:00:00:00:0e", "02:00:00:00:00:10"} {
		if skipped[m] == "" {
			t.Errorf("%s not skipped (named %q)", m, named[m])
		}
	}
	if len(noLease) != 1 || !noLease["02:00:00:00:00:03"] {
		t.Errorf("waiting for a lease: %v", noLease)
	}
	if _, ok := skipped["02:00:00:00:00:0a"]; ok || named["02:00:00:00:00:0a"] != "" {
		t.Error("an entry already right was touched")
	}
	got := opsText(ops)
	for _, line := range []string{
		"uci_set dhcp.netgrip_devname_020000000001 host",
		"uci_add_list dhcp.netgrip_devname_020000000001.mac 02:00:00:00:00:01",
		"uci_set dhcp.netgrip_devname_020000000001.name X1C",
		"uci_set dhcp.netgrip_devname_020000000001." + devNamedOpt + " 1",
		"uci_set dhcp.netgrip_devname_020000000007.name New-name",
		"uci_set dhcp.netgrip_host_020000000008.name Desk-PC2",
		"uci_set dhcp.netgrip_host_020000000008." + devNamedOpt + " 1",
		"uci_set dhcp.netgrip_host_02000000000c.name Office-PC",
	} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in\n%s", line, got)
		}
	}
	for _, bad := range []string{"dhcp.mine", "dhcp.noname", "dhcp.two", "printer_dns", "netgrip_host_020000000009",
		"02000000000d", "020000000008.mac", "020000000007.mac", "02000000000c.ip", "uci_delete"} {
		if strings.Contains(got, bad) {
			t.Errorf("touched %q:\n%s", bad, got)
		}
	}
}

// devNamesFake sets up a router with a DHCP config and leases for a pass.
type devNamesFake struct {
	dir      string
	applied  []string
	restored int
}

func newDevNamesFake(t *testing.T, leases string) *devNamesFake {
	f := &devNamesFake{dir: t.TempDir()}
	leaseFile := filepath.Join(f.dir, "dhcp.leases")
	if err := os.WriteFile(leaseFile, []byte(leases), 0o600); err != nil {
		t.Fatal(err)
	}
	oLeases, oMeta, oRec := leasesFilePath, clientMetaPath, devNamesRecordPath
	oLocal, oApply := devNamesLocalFn, devNamesApplyFn
	oRun, oSnap, oRestore := qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn
	oWait, oPending, oRecheck, oShow := qDnsmasqWaitFn, qUCIPendingFn, qDHCPRecheckDelay, uciShowFn
	t.Cleanup(func() {
		leasesFilePath, clientMetaPath, devNamesRecordPath = oLeases, oMeta, oRec
		devNamesLocalFn, devNamesApplyFn = oLocal, oApply
		qDnsmasqRuntimeFn, qSnapshotFn, qRestoreFn = oRun, oSnap, oRestore
		qDnsmasqWaitFn, qUCIPendingFn, qDHCPRecheckDelay, uciShowFn = oWait, oPending, oRecheck, oShow
	})
	leasesFilePath, clientMetaPath = leaseFile, filepath.Join(f.dir, "clients.json")
	devNamesRecordPath = filepath.Join(f.dir, "devnames.json")
	devNamesLocalFn = func() bool { return true }
	qDnsmasqWaitFn = func(time.Time) {}
	qUCIPendingFn = func(string) (string, error) { return "", nil }
	qDHCPRecheckDelay = 0
	uciShowFn = func(pkg string) (string, error) {
		if pkg != "dhcp" {
			return "", errors.New("unexpected")
		}
		return "dhcp.lan=dhcp\ndhcp.lan.interface='lan'\n", nil
	}
	qSnapshotFn = func(string) (string, error) { return "snap", nil }
	qRestoreFn = func(pkg, snap string) error { f.restored++; return nil }
	devNamesApplyFn = func(ops []executor.Op) error { f.applied = append(f.applied, opsText(ops)); return nil }
	qDnsmasqRuntimeFn = func() qDnsmasqServing { return qServing(qDnsmasqHealthy) }
	return f
}

func only(macs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range macs {
		m[x] = true
	}
	return m
}

func approveNamed(t *testing.T, names map[string]QApproved) {
	t.Helper()
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	for m, a := range names {
		st.Approved[m] = a
	}
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
}

// A pass names only the devices it is asked about, checks every network's
// DHCP afterwards, puts the DHCP config back when one lost it or dnsmasq
// stopped, and remembers what it wrote so it never writes it again.
func TestDevNamesPassChecksRestoresAndRemembers(t *testing.T) {
	newQFake(t)
	approveNamed(t, map[string]QApproved{
		"02:00:00:00:00:21": {Name: "X1C", Via: "manual"},
		"02:00:00:00:00:22": {Name: "espressif", Via: "baseline"},
		"02:00:00:00:00:23": {Name: "Lamp", Via: "manual"},
	})
	f := newDevNamesFake(t, "0 02:00:00:00:00:21 192.0.2.21 * 01:02\n0 02:00:00:00:00:22 192.0.2.22 * 01:03\n0 02:00:00:00:00:23 192.0.2.23 * 01:04\n")

	// Named by the user: only that device is written, with a check.
	devNamesPass(only("02:00:00:00:00:21"))
	if len(f.applied) != 1 || f.restored != 0 {
		t.Fatalf("applied %d, restored %d", len(f.applied), f.restored)
	}
	if !strings.Contains(f.applied[0], "dhcp.netgrip_devname_020000000021.name X1C") ||
		!strings.Contains(f.applied[0], "uci_commit dhcp") || !strings.Contains(f.applied[0], "initd dnsmasq reload") ||
		strings.Contains(f.applied[0], "020000000022") || strings.Contains(f.applied[0], "020000000023") {
		t.Fatalf("ops:\n%s", f.applied[0])
	}

	// The start's pass (nil) takes every typed name not written yet: not
	// X1C again (remembered, even though the fake config never shows it),
	// never a set-up label.
	f.applied = nil
	devNamesPass(nil)
	if len(f.applied) != 1 || !strings.Contains(f.applied[0], "020000000023.name Lamp") ||
		strings.Contains(f.applied[0], "espressif") || strings.Contains(f.applied[0], "X1C") {
		t.Fatalf("start's pass: %q", f.applied)
	}
	f.applied = nil
	devNamesPass(nil)
	if len(f.applied) != 0 {
		t.Fatalf("written again: %q", f.applied)
	}
	// Named again by the user with the same name: the config is looked at
	// (this fake config never shows the entry, as after a rollback), so
	// the name is written back.
	devNamesPass(only("02:00:00:00:00:21"))
	if len(f.applied) != 1 || !strings.Contains(f.applied[0], "020000000021.name X1C") {
		t.Fatalf("named again after the entry was lost: %q", f.applied)
	}
	f.applied = nil

	// A new name for X1C: written; a reload after which a network has no
	// DHCP: put back, and not remembered (so tried again later).
	approveNamed(t, map[string]QApproved{"02:00:00:00:00:21": {Name: "Printer", Via: "manual"}})
	calls := 0
	qDnsmasqRuntimeFn = func() qDnsmasqServing {
		calls++
		if calls == 1 {
			return qServing(qDnsmasqHealthy)
		}
		return qServing("bind-dynamic\ndhcp-range=set:lan,192.0.2.100,192.0.2.249,255.255.255.0,12h\n")
	}
	devNamesPass(only("02:00:00:00:00:21"))
	if f.restored != 1 || len(f.applied) != 2 || !strings.Contains(f.applied[1], "initd dnsmasq reload") {
		t.Fatalf("restored %d, applied %q", f.restored, f.applied)
	}
	if devNamesRecord()["02:00:00:00:00:21"] != "X1C" {
		t.Fatalf("an undone name was remembered: %v", devNamesRecord())
	}

	// dnsmasq not running after the reload: put back too.
	f.applied = nil
	qDnsmasqRuntimeFn = func() qDnsmasqServing { return qServing(qDnsmasqHealthy) }
	running := 0
	devNamesLocalFn = func() bool { running++; return running == 1 }
	devNamesPass(only("02:00:00:00:00:21"))
	if f.restored != 2 {
		t.Fatalf("dnsmasq stopped and nothing was put back (restored %d)", f.restored)
	}
	devNamesLocalFn = func() bool { return true }

	// Pending DHCP changes made by someone else: nothing is written.
	f.applied = nil
	qUCIPendingFn = func(string) (string, error) { return "dhcp.lan.start='100'", nil }
	devNamesPass(only("02:00:00:00:00:21"))
	if len(f.applied) != 0 {
		t.Fatalf("wrote over pending changes: %q", f.applied)
	}

	// An access point (DHCP served elsewhere): nothing at all.
	qUCIPendingFn = func(string) (string, error) { return "", nil }
	devNamesLocalFn = func() bool { return false }
	devNamesPass(nil)
	if len(f.applied) != 0 {
		t.Fatalf("an access point wrote DHCP: %q", f.applied)
	}
}

// A device named before it has a lease waits for one; a label saved back
// from the edit dialog is still not written.
func TestDevNamesWaitsForALeaseAndIgnoresEchoedLabels(t *testing.T) {
	newQFake(t)
	approveNamed(t, map[string]QApproved{
		"02:00:00:00:00:31": {Name: "Camera", Via: "manual"},
		"02:00:00:00:00:32": {Name: "espressif", Via: "baseline"},
	})
	f := newDevNamesFake(t, "0 02:00:00:00:00:32 192.0.2.32 * 01:03\n")
	if err := os.WriteFile(clientMetaPath, []byte(`{"02:00:00:00:00:32":{"name":"Espressif","device_type":"iot"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	waiting := devNamesPass(only("02:00:00:00:00:31", "02:00:00:00:00:32"))
	if len(f.applied) != 0 || !waiting["02:00:00:00:00:31"] || len(waiting) != 1 {
		t.Fatalf("applied %q, waiting %v", f.applied, waiting)
	}
	if got := devNamesLeased(waiting); len(got) != 0 {
		t.Fatalf("no lease yet, found %v", got)
	}
	if err := os.WriteFile(leasesFilePath, []byte("0 02:00:00:00:00:31 192.0.2.31 * 01:02\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := devNamesLeased(waiting)
	if !seen["02:00:00:00:00:31"] {
		t.Fatalf("the lease was not found: %v", seen)
	}
	if left := devNamesPass(seen); len(left) != 0 || len(f.applied) != 1 || !strings.Contains(f.applied[0], "020000000031.name Camera") {
		t.Fatalf("left %v, applied %q", left, f.applied)
	}
}

// Naming queues only those devices and wakes the worker without blocking.
func TestKickDeviceNames(t *testing.T) {
	devNamesQueueMu.Lock()
	devNamesQueue = map[string]bool{}
	devNamesQueueMu.Unlock()
	kickDeviceNames("02:00:00:00:00:21", " 02:00:00:00:00:2A ")
	kickDeviceNames("02:00:00:00:00:21") // a second kick never blocks
	devNamesQueueMu.Lock()
	q := devNamesQueue
	devNamesQueue = map[string]bool{}
	devNamesQueueMu.Unlock()
	if len(q) != 2 || !q["02:00:00:00:00:21"] || !q["02:00:00:00:00:2a"] {
		t.Fatalf("queue: %v", q)
	}
	select {
	case <-devNamesKickCh:
	default:
		t.Fatal("the worker was not woken")
	}
}

// Reserving reuses a device's NetGrip naming entry (one dhcp-host line per
// MAC); removing a reservation keeps a name; a reservation with no name
// goes whole, as before.
func TestReservationOps(t *testing.T) {
	keys := func(k ...string) func(string) (string, bool) {
		m := map[string]string{}
		for _, x := range k {
			m[x] = ""
			if strings.HasSuffix(x, ".mac") {
				m[x] = "02:00:00:00:00:41"
			}
		}
		return func(key string) (string, bool) { v, ok := m[key]; return v, ok }
	}
	const mac, ip = "02:00:00:00:00:41", "192.0.2.41"
	named := "dhcp.netgrip_devname_020000000041"
	reserve := "dhcp.netgrip_host_020000000041"
	for _, c := range []struct {
		name     string
		reserved bool
		exists   func(string) (string, bool)
		want     string
	}{
		{"new reservation", true, keys(),
			"uci_set " + reserve + " host\nuci_set " + reserve + ".mac " + mac + "\nuci_set " + reserve + ".ip " + ip + "\n"},
		{"reserve a named device", true, keys(named, named+".name", named+".mac"),
			"uci_set " + named + ".ip " + ip + "\n"},
		{"change an existing reservation", true, keys(reserve, reserve+".ip"),
			"uci_set " + reserve + ".ip " + ip + "\n"},
		{"unreserve a named device", false, keys(named, named+".name", named+".mac", named+".ip"),
			"uci_delete " + named + ".ip\n"},
		{"unreserve a reservation NetGrip named", false, keys(reserve, reserve+".name", reserve+".ip"),
			"uci_delete " + reserve + ".ip\n"},
		{"unreserve a plain reservation", false, keys(reserve, reserve+".ip"),
			"uci_delete " + reserve + "\n"},
		{"unreserve nothing", false, keys(), ""},
		{"a naming entry whose MAC was changed by hand is not used", true,
			func(key string) (string, bool) {
				switch key {
				case named, named + ".name":
					return "", true
				case named + ".mac":
					return "02:00:00:00:00:99", true
				}
				return "", false
			},
			"uci_set " + reserve + " host\nuci_set " + reserve + ".mac " + mac + "\nuci_set " + reserve + ".ip " + ip + "\n"},
	} {
		if got := opsText(reservationOps(mac, ip, c.reserved, c.exists)); got != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

func TestUciShellCommands(t *testing.T) {
	got := uciShellCommands([]executor.Op{
		{Kind: "uci_set", Args: []string{"dhcp.netgrip_host_020000000041", "host"}},
		{Kind: "uci_set", Args: []string{"dhcp.netgrip_host_020000000041.ip", "192.0.2.41"}},
		{Kind: "uci_delete", Args: []string{"dhcp.netgrip_devname_020000000041.ip"}},
	})
	want := []string{"uci set dhcp.netgrip_host_020000000041=host", "uci set dhcp.netgrip_host_020000000041.ip=192.0.2.41",
		"uci delete dhcp.netgrip_devname_020000000041.ip"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", got)
	}
}
