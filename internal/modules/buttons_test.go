package modules

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OpenWrt's stock /etc/rc.button/reset (base-files).
const btnStockReset = `#!/bin/sh

. /lib/functions.sh

OVERLAY="$( grep ' /overlay ' /proc/mounts )"

case "$ACTION" in
pressed)
	[ -z "$OVERLAY" ] && return 0

	return 5
;;
timeout)
	. /etc/diag.sh
	set_state failsafe
;;
released)
	if [ "$SEEN" -lt 1 ]
	then
		echo "REBOOT" > /dev/console
		sync
		reboot
	elif [ "$SEEN" -ge 5 -a -n "$OVERLAY" ]
	then
		echo "FACTORY RESET" > /dev/console
		factoryreset -y && reboot &
	fi
;;
esac

return 0
`

const btnStockWPS = `#!/bin/sh
[ "$ACTION" = "pressed" ] && exit 5
for script in /etc/rc.wps/*; do
	[ -x "$script" ] || continue
	"$script" && break
done
`

// btnTestRouter points every path of the feature at a temporary router.
func btnTestRouter(t *testing.T) (root string, enabled *[]bool) {
	t.Helper()
	root = t.TempDir()
	set := func(p *string, v string) {
		old := *p
		*p = v
		t.Cleanup(func() { *p = old })
	}
	set(&btnRunnerPath, filepath.Join(root, "usr/libexec/netgrip-button"))
	set(&btnRcDir, filepath.Join(root, "etc/rc.button"))
	set(&btnRomRcDir, filepath.Join(root, "rom/etc/rc.button"))
	set(&btnRcdDir, filepath.Join(root, "etc/rc.d"))
	set(&btnEtcDir, filepath.Join(root, "etc/netgrip/buttons"))
	set(&btnStateDir, filepath.Join(root, "tmp/netgrip-buttons"))
	set(&btnHookPath, filepath.Join(root, "etc/hotplug.d/button/00-netgrip"))
	set(&btnInitPath, filepath.Join(root, "etc/init.d/netgrip-buttons"))
	set(&btnLedsDir, filepath.Join(root, "sys/class/leds"))
	set(&btnDTDir, filepath.Join(root, "sys/firmware/devicetree/base"))
	if err := os.MkdirAll(btnRcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := []bool{}
	enabled = &calls
	oldInit := btnInitEnableFn
	// Like rc.common: enable makes the S<NN> link, disable removes it.
	btnInitEnableFn = func(on bool) error {
		calls = append(calls, on)
		link := filepath.Join(btnRcdDir, "S15"+filepath.Base(btnInitPath))
		if on {
			_ = os.MkdirAll(btnRcdDir, 0o755)
			return os.WriteFile(link, nil, 0o644)
		}
		return os.Remove(link)
	}
	t.Cleanup(func() { btnInitEnableFn = oldInit })
	oldUntil := btnListenUntil
	btnListenUntil = time.Time{}
	t.Cleanup(func() { btnListenUntil = oldUntil })
	return root, enabled
}

func btnWriteT(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func btnReadT(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func btnExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestBtnLineRoundTrip(t *testing.T) {
	for _, a := range []ButtonAction{
		{Button: "reset", Trigger: "press", Count: 3, Action: "wifi_toggle", Iface: "guest_ap", Minutes: 30},
		{Button: "wps", Trigger: "hold", Seconds: 4, Action: "access_restart"},
		{Button: "BTN_0", Trigger: "press", Count: 1, Action: "firewall_restart"},
	} {
		got, ok := btnParseLine(btnLine(a))
		if !ok || got != a {
			t.Errorf("round trip of %+v = %+v, %v", a, got, ok)
		}
	}
	for _, bad := range []string{"", "reset press 1", "reset press x wifi_toggle - 0", "a b c d e f g"} {
		if _, ok := btnParseLine(bad); ok {
			t.Errorf("btnParseLine(%q) accepted", bad)
		}
	}
}

func TestBtnReservedAndStock(t *testing.T) {
	cases := []struct {
		script   string
		reserved int
		stock    string
	}{
		{btnStockReset, 5, "reset"},
		{btnStockWPS, 0, "wps"},
		{"#!/bin/sh\nfactoryreset -y\n", btnHoldMin, "reset"}, // resets, but when is unclear
		{"#!/bin/sh\n[ \"$SEEN\" -ge 10 ] && jffs2reset -y\n[ \"$SEEN\" -ge 3 ] && reboot\n", 3, "reset"},
		{"#!/bin/sh\nexec /sbin/poweroff\n", 0, "power"},
		{"#!/bin/sh\n[ \"$SEEN\" -gt 5 ] && firstboot -y\n", 6, "reset"}, // more than 5 s: from 6

		{"#!/bin/sh\nlogger hi\n", 0, "custom"},
		{"", 0, ""},
	}
	for i, c := range cases {
		if got := btnReservedIn(c.script); got != c.reserved {
			t.Errorf("case %d: reserved = %d, want %d", i, got, c.reserved)
		}
		if got := btnStock(c.script); got != c.stock {
			t.Errorf("case %d: stock = %q, want %q", i, got, c.stock)
		}
	}
}

// btnFakeWireless answers uci for a wireless config with the given AP
// sections.
func btnFakeWireless(t *testing.T, aps ...string) {
	t.Helper()
	SetUciExecForTest(t, func(args ...string) ([]byte, error) {
		if len(args) >= 3 && args[0] == "-q" && args[1] == "get" {
			for _, ap := range aps {
				if args[2] == "wireless."+ap {
					return []byte("wifi-iface\n"), nil
				}
			}
		}
		return nil, errors.New("not found")
	})
}

func TestValidateButtons(t *testing.T) {
	root, _ := btnTestRouter(t)
	btnFakeWireless(t, "guest_ap")
	btnWriteT(t, filepath.Join(root, "sys/class/leds/green:status/trigger"), "[none] timer\n")
	reserved := func(b string) int {
		if b == "reset" {
			return 5
		}
		return 0
	}
	ok := ButtonsConfig{LED: "green:status", Actions: []ButtonAction{
		{Button: "wps", Trigger: "hold", Seconds: 10, Action: "firewall_restart", Iface: "x", Minutes: 9},
		{Button: "reset", Trigger: "press", Count: 3, Action: "wifi_toggle", Iface: "guest_ap", Minutes: 30},
		{Button: "reset", Trigger: "hold", Seconds: 4, Action: "access_restart"},
		{Button: "reset", Trigger: "press", Count: 1, Action: "firewall_restart"},
	}}
	if err := validateButtons(&ok, reserved); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	// Sorted per button, presses first; options an action does not use
	// are dropped.
	want := []string{"reset press 1", "reset press 3", "reset hold 4", "wps hold 10"}
	for i, a := range ok.Actions {
		if got := strings.Join(strings.Fields(btnLine(a))[:3], " "); got != want[i] {
			t.Errorf("action %d = %q, want %q", i, got, want[i])
		}
	}
	if a := ok.Actions[3]; a.Iface != "" || a.Minutes != 0 {
		t.Errorf("firewall action kept wifi options: %+v", a)
	}

	bad := map[string]ButtonsConfig{
		"hold into the factory reset": {Actions: []ButtonAction{{Button: "reset", Trigger: "hold", Seconds: 5, Action: "firewall_restart"}}},
		"same press twice": {Actions: []ButtonAction{
			{Button: "wps", Trigger: "press", Count: 1, Action: "firewall_restart"},
			{Button: "wps", Trigger: "press", Count: 1, Action: "access_restart"},
		}},
		"failsafe":         {Actions: []ButtonAction{{Button: "failsafe", Trigger: "press", Count: 1, Action: "firewall_restart"}}},
		"path in the name": {Actions: []ButtonAction{{Button: "../x", Trigger: "press", Count: 1, Action: "firewall_restart"}}},
		"four presses":     {Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 4, Action: "firewall_restart"}}},
		"one second hold":  {Actions: []ButtonAction{{Button: "wps", Trigger: "hold", Seconds: 1, Action: "firewall_restart"}}},
		"unknown action":   {Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 1, Action: "reboot"}}},
		"unknown network":  {Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 1, Action: "wifi_toggle", Iface: "nope"}}},
		"shell in network": {Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 1, Action: "wifi_toggle", Iface: "a;b"}}},
		"too long":         {Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 1, Action: "wifi_toggle", Iface: "guest_ap", Minutes: 1441}}},
		"missing LED":      {LED: "red:none"},
	}
	for name, cfg := range bad {
		if err := validateButtons(&cfg, reserved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBtnApplyInstallsRepairsAndRestores(t *testing.T) {
	root, enabled := btnTestRouter(t)
	reset := filepath.Join(btnRcDir, "reset")
	btnWriteT(t, reset, btnStockReset)
	btnWriteT(t, filepath.Join(btnRcDir, "wps"), btnStockWPS)

	cfg := ButtonsConfig{Actions: []ButtonAction{
		{Button: "reset", Trigger: "press", Count: 2, Action: "wifi_toggle", Iface: "guest_ap", Minutes: 15},
		{Button: "BTN_0", Trigger: "press", Count: 1, Action: "firewall_restart"},
	}, LED: "green:status"}
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	w := btnReadT(t, reset)
	if !btnIsOurs([]byte(w)) || !strings.Contains(w, "rc 'reset' 5") {
		t.Fatalf("reset wrapper wrong:\n%s", w)
	}
	if got := btnReadT(t, filepath.Join(btnEtcDir, "orig/reset")); got != btnStockReset {
		t.Fatalf("original not kept intact")
	}
	if btnReadT(t, filepath.Join(btnRcDir, "wps")) != btnStockWPS {
		t.Fatalf("a button without actions was touched")
	}
	if !btnExists(filepath.Join(btnRcDir, "BTN_0")) || btnExists(filepath.Join(btnEtcDir, "orig/BTN_0")) {
		t.Fatalf("a button without a script gets a wrapper and no kept original")
	}
	if st, err := os.Stat(btnRunnerPath); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("runner not installed executable: %v", err)
	}
	actions := btnReadT(t, filepath.Join(btnEtcDir, "actions"))
	if !strings.Contains(actions, "reset press 2 wifi_toggle guest_ap 15\n") || !strings.Contains(actions, "BTN_0 press 1 firewall_restart - 0\n") {
		t.Fatalf("actions file:\n%s", actions)
	}
	if btnReadT(t, filepath.Join(btnEtcDir, "led")) != "green:status\n" {
		t.Fatalf("led file wrong")
	}
	if !btnExists(btnHookPath) || !btnExists(btnInitPath) || len(*enabled) == 0 || !(*enabled)[len(*enabled)-1] {
		t.Fatalf("hook/boot script not in place (enabled calls %v)", *enabled)
	}
	// Applying again (each start, each panel visit) touches nothing.
	before := len(*enabled)
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	if len(*enabled) != before {
		t.Fatalf("the boot script was enabled again: %v", *enabled)
	}

	// An upgrade writes a new stock script over the wrapper: the new one
	// becomes the kept original and the wrapper comes back.
	newer := strings.Replace(btnStockReset, "-ge 5", "-ge 7", 1)
	btnWriteT(t, reset, newer)
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	if btnReadT(t, filepath.Join(btnEtcDir, "orig/reset")) != newer {
		t.Fatalf("the upgraded script was not kept as the original")
	}
	if w := btnReadT(t, reset); !strings.Contains(w, "rc 'reset' 7") {
		t.Fatalf("wrapper not repaired with the new reserved hold:\n%s", w)
	}

	// Nothing assigned: every original back, nothing of the feature left.
	if err := btnApplyLocked(ButtonsConfig{}); err != nil {
		t.Fatal(err)
	}
	if btnReadT(t, reset) != newer {
		t.Fatalf("reset script not restored")
	}
	for _, p := range []string{filepath.Join(btnRcDir, "BTN_0"), btnRunnerPath, btnHookPath, btnInitPath, filepath.Join(btnEtcDir, "orig/reset"), btnEtcDir} {
		if btnExists(p) {
			t.Errorf("%s left behind", strings.TrimPrefix(p, root))
		}
	}
	if (*enabled)[len(*enabled)-1] {
		t.Errorf("boot script not disabled")
	}
	if btnReadT(t, filepath.Join(btnRcDir, "wps")) != btnStockWPS {
		t.Fatalf("wps changed")
	}
}

func TestBtnReservedForUnrecognisedReset(t *testing.T) {
	// A vendor reset script NetGrip cannot read: no hold on "reset".
	vendor := "#!/bin/sh\n[ \"$SEEN\" -ge 8 ] && /usr/bin/vendor-erase\n"
	if got := btnReservedFor("reset", vendor); got != btnHoldMin {
		t.Fatalf("unrecognised reset script: reserved %d, want %d", got, btnHoldMin)
	}
	if got := btnReservedFor("BTN_1", vendor); got != 0 {
		t.Fatalf("other button: reserved %d, want 0", got)
	}
	if got := btnReservedFor("reset", btnStockReset); got != 5 {
		t.Fatalf("stock reset: reserved %d", got)
	}
}

func TestValidateButtonsRefusesSwitches(t *testing.T) {
	_, _ = btnTestRouter(t)
	btnWriteT(t, filepath.Join(btnStateDir, "seen.rfkill"), "switch\n")
	btnWriteT(t, filepath.Join(btnStateDir, "seen.wps"), "-\n")
	sw := ButtonsConfig{Actions: []ButtonAction{{Button: "rfkill", Trigger: "press", Count: 1, Action: "firewall_restart"}}}
	if err := validateButtons(&sw, func(string) int { return 0 }); err == nil {
		t.Fatal("a switch was accepted")
	}
	ok := ButtonsConfig{Actions: []ButtonAction{{Button: "wps", Trigger: "press", Count: 1, Action: "firewall_restart"}}}
	if err := validateButtons(&ok, func(string) int { return 0 }); err != nil {
		t.Fatalf("a button was refused: %v", err)
	}
}

func TestBtnLostCopyFallsBackToFirmware(t *testing.T) {
	_, _ = btnTestRouter(t)
	reset := filepath.Join(btnRcDir, "reset")
	btnWriteT(t, reset, btnStockReset)
	btnWriteT(t, filepath.Join(btnRomRcDir, "reset"), btnStockReset)
	cfg := ButtonsConfig{Actions: []ButtonAction{{Button: "reset", Trigger: "press", Count: 2, Action: "firewall_restart"}}}
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	// NetGrip's kept copy is lost (flash cleaned by hand, say).
	os.RemoveAll(filepath.Join(btnEtcDir, "orig"))
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	if w := btnReadT(t, reset); !strings.Contains(w, "rc 'reset' 5") {
		t.Fatalf("the factory reset hold was lost with the copy:\n%s", w)
	}
	if err := btnApplyLocked(ButtonsConfig{}); err != nil {
		t.Fatal(err)
	}
	if btnReadT(t, reset) != btnStockReset {
		t.Fatal("the firmware's script was not put back")
	}
}

func TestBtnApplyLeavesForeignFiles(t *testing.T) {
	_, _ = btnTestRouter(t)
	// Someone else's hook and boot script with the same names are not
	// NetGrip's to remove.
	btnWriteT(t, btnHookPath, "# mine\n")
	btnWriteT(t, btnInitPath, "#!/bin/sh\n# mine\n")
	if err := btnApplyLocked(ButtonsConfig{}); err != nil {
		t.Fatal(err)
	}
	if !btnExists(btnHookPath) || !btnExists(btnInitPath) {
		t.Fatal("a file NetGrip did not write was removed")
	}
}

func TestBtnApplyKeepsBootScriptWhileTimed(t *testing.T) {
	_, enabled := btnTestRouter(t)
	btnWriteT(t, filepath.Join(btnEtcDir, "timed/guest_ap"), "1 tok\n")
	if err := btnApplyLocked(ButtonsConfig{}); err != nil {
		t.Fatal(err)
	}
	if !btnExists(btnInitPath) || !btnExists(btnRunnerPath) {
		t.Fatal("a running timed toggle lost its boot script or runner")
	}
	if len(*enabled) == 0 || !(*enabled)[len(*enabled)-1] {
		t.Fatal("boot script not enabled")
	}
	if btnExists(btnHookPath) {
		t.Fatal("hook installed with nothing assigned")
	}
}

func TestBtnBoardButtons(t *testing.T) {
	_, _ = btnTestRouter(t)
	code := func(n uint32) string {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, n)
		return string(b)
	}
	btnWriteT(t, filepath.Join(btnDTDir, "keys/compatible"), "gpio-keys\x00")
	btnWriteT(t, filepath.Join(btnDTDir, "keys/k1/linux,code"), code(0x198))
	btnWriteT(t, filepath.Join(btnDTDir, "keys/k2/linux,code"), code(0x211))
	btnWriteT(t, filepath.Join(btnDTDir, "keys/k3/linux,code"), code(0x7777)) // unknown: left out
	btnWriteT(t, filepath.Join(btnDTDir, "soc/buttons/compatible"), "gpio-keys-polled\x00")
	btnWriteT(t, filepath.Join(btnDTDir, "soc/buttons/b/linux,code"), code(0x100))
	btnWriteT(t, filepath.Join(btnDTDir, "leds/compatible"), "gpio-leds\x00")
	btnWriteT(t, filepath.Join(btnDTDir, "leds/l/linux,code"), code(0x198))
	got := strings.Join(btnBoardButtons(), ",")
	if got != "BTN_0,reset,wps" {
		t.Fatalf("board buttons = %q", got)
	}
}

func TestBtnEventText(t *testing.T) {
	ssid := map[string]string{"guest_ap": "Guest"}
	cases := []struct {
		e    ButtonEvent
		want string
	}{
		{ButtonEvent{Button: "reset", Pattern: "press3", Action: "wifi_toggle", Detail: "guest_ap on 30", Result: "ok"}, `Button reset pressed 3 times: Wi-Fi "Guest" turned on for 30 min`},
		{ButtonEvent{Button: "reset", Pattern: "press2", Action: "wifi_toggle", Detail: "guest_ap off 0", Result: "ok"}, `Button reset pressed twice: Wi-Fi "Guest" turned off`},
		{ButtonEvent{Button: "reset", Pattern: "timer", Action: "wifi_toggle", Detail: "guest_ap off 30", Result: "reverted"}, `Wi-Fi "Guest" is off again after 30 min`},
		{ButtonEvent{Button: "boot", Pattern: "timer", Action: "wifi_toggle", Detail: "guest_ap off 0", Result: "reverted"}, `Wi-Fi "Guest" is off again: the router restarted before its time was up`},
		{ButtonEvent{Button: "wps", Pattern: "hold4", Action: "access_restart", Detail: "dropbear,netgrip", Result: "ok"}, `Button wps held 4 s: restarted dropbear, netgrip`},
		{ButtonEvent{Button: "wps", Pattern: "press1", Action: "firewall_restart", Detail: "-", Result: "failed"}, `Button wps pressed: restarting the firewall failed`},
	}
	for _, c := range cases {
		if got := btnEventText(c.e, ssid); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

func TestBtnNotifyNewOncePerEvent(t *testing.T) {
	_, _ = btnTestRouter(t)
	SetUciExecForTest(t, func(args ...string) ([]byte, error) { return nil, errors.New("none") })
	var sent []string
	oldN, oldC := btnNotifyFn, btnChannelFn
	btnNotifyFn = func(_, _, text string, _ bool) { sent = append(sent, text) }
	btnChannelFn = func() bool { return true }
	t.Cleanup(func() { btnNotifyFn, btnChannelFn = oldN, oldC })

	events := filepath.Join(btnStateDir, "events")
	btnWriteT(t, events, "100\t1700000000\twps\tpress1\tfirewall_restart\t-\tok\n")
	btnNotifyNew()
	btnNotifyNew()
	if len(sent) != 1 || !strings.Contains(sent[0], "firewall restarted") {
		t.Fatalf("sent = %q", sent)
	}
	f, _ := os.OpenFile(events, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("250\t1700000005\twps\thold3\taccess_restart\tdropbear\tok\nbroken line\n")
	f.Close()
	btnNotifyNew()
	if len(sent) != 2 || !strings.Contains(sent[1], "restarted dropbear") {
		t.Fatalf("sent = %q", sent)
	}
	if got := btnReadT(t, filepath.Join(btnStateDir, "notified")); strings.TrimSpace(got) != "250" {
		t.Fatalf("mark = %q", got)
	}
}

func TestBtnScheduleHeld(t *testing.T) {
	_, _ = btnTestRouter(t)
	now := time.Unix(1_700_000_000, 0)
	oldNow := btnNow
	btnNow = func() time.Time { return now }
	t.Cleanup(func() { btnNow = oldNow })
	hold := filepath.Join(btnStateDir, "hold", "guest_ap")

	if btnScheduleHeld("guest_ap", true) {
		t.Fatal("held without a hold file")
	}
	// A timed toggle holds the schedule until its end.
	btnWriteT(t, hold, "1700000600 tok1\n")
	if !btnScheduleHeld("guest_ap", true) {
		t.Fatal("timed toggle not held")
	}
	now = now.Add(11 * time.Minute)
	if btnScheduleHeld("guest_ap", true) || btnExists(hold) {
		t.Fatal("an ended timed toggle still holds the schedule")
	}
	// A toggle without a time holds it until the schedule changes.
	btnWriteT(t, hold, "0 tok2\n")
	for i := 0; i < 3; i++ {
		if !btnScheduleHeld("guest_ap", true) {
			t.Fatalf("tick %d: not held", i)
		}
	}
	if btnScheduleHeld("guest_ap", false) || btnExists(hold) {
		t.Fatal("the schedule changing did not end the hold")
	}
	// A new toggle (new token) starts over, whatever the schedule says.
	btnWriteT(t, hold, "0 tok3\n")
	if !btnScheduleHeld("guest_ap", false) || !btnScheduleHeld("guest_ap", false) {
		t.Fatal("new toggle not held")
	}
}

// TestBtnRunnerScript runs the shell runner with fake commands: presses,
// holds, the reserved factory reset and forwarding to the original. The
// target is busybox ash; any POSIX sh with flock and setsid checks the
// logic here (the router run covers ash itself).
func TestBtnRunnerScript(t *testing.T) {
	for _, tool := range []string{"sh", "flock", "setsid", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	if _, err := os.Stat("/proc/uptime"); err != nil {
		t.Skip("no /proc/uptime")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	logf := filepath.Join(dir, "log")
	runner := filepath.Join(dir, "runner")
	btnWriteT(t, runner, string(btnRunnerScript))
	btnWriteT(t, filepath.Join(bin, "uci"), "#!/bin/sh\necho \"uci $*\" >> "+logf+"\n")
	btnWriteT(t, filepath.Join(bin, "wifi"), "#!/bin/sh\necho \"wifi $*\" >> "+logf+"\n")
	btnWriteT(t, filepath.Join(bin, "logger"), "#!/bin/sh\n:\n")
	for _, s := range []string{"firewall", "dropbear"} {
		btnWriteT(t, filepath.Join(dir, "initd", s), "#!/bin/sh\n[ \"$1\" = enabled ] && exit 0\necho \"initd "+s+" $1\" >> "+logf+"\n")
	}
	btnWriteT(t, filepath.Join(dir, "etc/orig/reset"), "#!/bin/sh\necho \"orig $ACTION $SEEN\" >> "+logf+"\n[ \"$ACTION\" = pressed ] && exit 5\nexit 0\n")
	btnWriteT(t, filepath.Join(dir, "etc/actions"), "reset press 1 firewall_restart - 0\nreset hold 2 access_restart - 0\n")
	env := append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"NGB_STATE="+filepath.Join(dir, "state"),
		"NGB_ETC="+filepath.Join(dir, "etc"),
		"NGB_SELF="+runner,
		"NGB_INITD="+filepath.Join(dir, "initd"),
		"NGB_LEDS="+filepath.Join(dir, "leds"),
		"NGB_ROMRC="+filepath.Join(dir, "rom"),
		"NGB_CONFIG="+filepath.Join(dir, "config"),
	)
	run := func(action, seen string) int {
		cmd := exec.Command("sh", runner, "rc", "reset", "5")
		cmd.Env = append(env, "BUTTON=reset", "ACTION="+action, "SEEN="+seen)
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}
	waitFor := func(want string) {
		t.Helper()
		for i := 0; i < 40; i++ {
			if data, _ := os.ReadFile(logf); strings.Contains(string(data), want) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		data, _ := os.ReadFile(logf)
		t.Fatalf("%q never logged:\n%s", want, data)
	}
	logged := func() string { data, _ := os.ReadFile(logf); return string(data) }

	if code := run("pressed", "0"); code != 5 {
		t.Fatalf("pressed: exit %d, want the original's 5", code)
	}
	waitFor("orig pressed 0")
	run("released", "0") // only single presses assigned: runs at once
	waitFor("initd firewall restart")
	run("released", "3")
	waitFor("initd dropbear restart")
	os.Remove(logf)
	run("timeout", "5") // reserved button: the original's LED warning
	waitFor("orig timeout 5")
	run("released", "6") // factory reset hold: always the original
	waitFor("orig released 6")
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(logged(), "initd") {
		t.Fatalf("a reserved hold ran an action:\n%s", logged())
	}
	events := btnReadT(t, filepath.Join(dir, "state/events"))
	if !strings.Contains(events, "\treset\tpress1\tfirewall_restart\t-\tok") || !strings.Contains(events, "\treset\thold2\taccess_restart\tdropbear\tok") {
		t.Fatalf("events:\n%s", events)
	}
}

func TestBtnHadNoScriptStaysWithout(t *testing.T) {
	_, _ = btnTestRouter(t)
	// The user removed reset's script; the firmware image still has it.
	btnWriteT(t, filepath.Join(btnRomRcDir, "reset"), btnStockReset)
	cfg := ButtonsConfig{Actions: []ButtonAction{{Button: "reset", Trigger: "press", Count: 2, Action: "firewall_restart"}}}
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := btnOriginal("reset"); ok {
		t.Fatal("the firmware's script counts as the original of a button that had none")
	}
	w := btnReadT(t, filepath.Join(btnRcDir, "reset"))
	if !strings.Contains(w, ".none ] && exit 0") {
		t.Fatalf("wrapper falls back to the firmware's script:\n%s", w)
	}
	if err := btnApplyLocked(ButtonsConfig{}); err != nil {
		t.Fatal(err)
	}
	if btnExists(filepath.Join(btnRcDir, "reset")) {
		t.Fatal("removing the actions brought the firmware's script back")
	}
	if btnExists(filepath.Join(btnEtcDir, "orig", "reset.none")) {
		t.Fatal("marker left behind")
	}
}

// btnRunnerEnv prepares a runner with fake commands in a temporary router.
func btnRunnerEnv(t *testing.T, actions string) (dir string, env []string, logf string) {
	t.Helper()
	for _, tool := range []string{"sh", "flock", "setsid", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	if _, err := os.Stat("/proc/uptime"); err != nil {
		t.Skip("no /proc/uptime")
	}
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	logf = filepath.Join(dir, "log")
	btnWriteT(t, filepath.Join(dir, "runner"), string(btnRunnerScript))
	btnWriteT(t, filepath.Join(bin, "logger"), "#!/bin/sh\n:\n")
	btnWriteT(t, filepath.Join(bin, "uci"), "#!/bin/sh\necho \"uci $*\" >> "+logf+"\n")
	btnWriteT(t, filepath.Join(dir, "initd", "firewall"), "#!/bin/sh\n[ \"$1\" = enabled ] && exit 0\necho \"initd firewall $1\" >> "+logf+"\n")
	btnWriteT(t, filepath.Join(dir, "etc/orig/reset"), "#!/bin/sh\necho \"orig $ACTION $SEEN\" >> "+logf+"\n")
	btnWriteT(t, filepath.Join(dir, "etc/actions"), actions)
	env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"NGB_STATE="+filepath.Join(dir, "state"),
		"NGB_ETC="+filepath.Join(dir, "etc"),
		"NGB_SELF="+filepath.Join(dir, "runner"),
		"NGB_INITD="+filepath.Join(dir, "initd"),
		"NGB_LEDS="+filepath.Join(dir, "leds"),
		"NGB_ROMRC="+filepath.Join(dir, "rom"),
		"NGB_RCDIR="+filepath.Join(dir, "rc"),
		"NGB_HOOK="+filepath.Join(dir, "hook/00-netgrip"),
		"NGB_CONFIG="+filepath.Join(dir, "config"),
	)
	return dir, env, logf
}

func btnWaitLog(t *testing.T, logf, want string) {
	t.Helper()
	for i := 0; i < 40; i++ {
		if data, _ := os.ReadFile(logf); strings.Contains(string(data), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, _ := os.ReadFile(logf)
	t.Fatalf("%q never logged:\n%s", want, data)
}

func TestBtnRunnerSlowAndExtraPresses(t *testing.T) {
	dir, env, logf := btnRunnerEnv(t, "reset press 2 firewall_restart - 0\n")
	release := func(seen string) {
		cmd := exec.Command("sh", filepath.Join(dir, "runner"), "rc", "reset", "5")
		cmd.Env = append(env, "BUTTON=reset", "ACTION=released", "SEEN="+seen)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	// A slow single press (1 s) goes to the original with SEEN=1: the
	// stock reset script restarts the router only under a second.
	release("1")
	btnWaitLog(t, logf, "orig released 1")
	time.Sleep(1500 * time.Millisecond)
	os.Remove(logf)
	// Double press, then one press too many: the third is absorbed.
	release("0")
	release("0")
	btnWaitLog(t, logf, "initd firewall restart")
	release("0")
	time.Sleep(2500 * time.Millisecond)
	if data, _ := os.ReadFile(logf); strings.Contains(string(data), "orig released") {
		t.Fatalf("the extra press reached the original:\n%s", data)
	}
}

func TestBtnWrapperWithoutRunner(t *testing.T) {
	_, _ = btnTestRouter(t)
	logf := filepath.Join(t.TempDir(), "log")
	btnWriteT(t, filepath.Join(btnRcDir, "reset"), "#!/bin/sh\necho \"orig $ACTION\" >> "+logf+"\nexit 5\n")
	cfg := ButtonsConfig{Actions: []ButtonAction{{Button: "reset", Trigger: "press", Count: 1, Action: "firewall_restart"}}}
	if err := btnApplyLocked(cfg); err != nil {
		t.Fatal(err)
	}
	os.Remove(btnRunnerPath)
	cmd := exec.Command("sh", filepath.Join(btnRcDir, "reset"))
	cmd.Env = append(os.Environ(), "ACTION=pressed", "BUTTON=reset")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 5 {
		t.Fatalf("wrapper without runner: %v, want the original's exit 5", err)
	}
	if !strings.Contains(btnReadT(t, logf), "orig pressed") {
		t.Fatal("the original did not run")
	}
}

func TestBtnRunnerUninstall(t *testing.T) {
	dir, env, _ := btnRunnerEnv(t, "reset press 1 firewall_restart - 0\n")
	btnWriteT(t, filepath.Join(dir, "rc/reset"), "#!/bin/sh\n# netgrip-managed-button\n")
	btnWriteT(t, filepath.Join(dir, "rc/BTN_0"), "#!/bin/sh\n# netgrip-managed-button\n")
	btnWriteT(t, filepath.Join(dir, "rc/wps"), "#!/bin/sh\n# stock\n")
	btnWriteT(t, filepath.Join(dir, "hook/00-netgrip"), "# netgrip-managed-button\n")
	cmd := exec.Command("sh", filepath.Join(dir, "runner"), "uninstall")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall: %v %s", err, out)
	}
	if got := btnReadT(t, filepath.Join(dir, "rc/reset")); !strings.Contains(got, "orig $ACTION") {
		t.Fatalf("reset not restored: %q", got)
	}
	if st, _ := os.Stat(filepath.Join(dir, "rc/reset")); st.Mode().Perm() != 0o755 {
		t.Fatalf("restored mode %v", st.Mode().Perm())
	}
	for _, p := range []string{"rc/BTN_0", "hook/00-netgrip", "etc", "runner", "state"} {
		if btnExists(filepath.Join(dir, p)) {
			t.Errorf("%s left behind", p)
		}
	}
	if btnReadT(t, filepath.Join(dir, "rc/wps")) != "#!/bin/sh\n# stock\n" {
		t.Error("a script NetGrip did not write was changed")
	}
}
