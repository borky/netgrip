package modules

// Router buttons: actions that run when a physical button on the router is
// pressed, meant to recover a router or get access to it again (turn a
// Wi-Fi network on for a while, restart the firewall, restart the services
// that give access).
//
// OpenWrt hands every button event to /etc/rc.button/<button> (procd's
// hotplug rules; the kernel's gpio-button-hotplug names the buttons). For a
// button with actions, NetGrip moves that script aside and puts a small
// wrapper in its place, which calls the runner (buttons/netgrip-button.sh,
// installed as /usr/libexec/netgrip-button). The runner runs the assigned
// actions and hands every other press to the original script, so a press
// nobody assigned does what it always did, and holding the reset button
// for its factory reset always works. The runner is shell and needs
// nothing from NetGrip at press time: a broken panel does not stop it.
// Nothing runs between presses; NetGrip only reads the runner's log (by
// inotify) to show and notify what ran.
//
// The actions live in UCI (netgrip.buttons), so a configuration backup
// keeps them; NetGrip writes the runner's own copy (/etc/netgrip/buttons/
// actions) from it. An upgrade that replaces a button script, or a
// sysupgrade, is repaired when NetGrip starts or the panel opens the card.

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
)

//go:embed buttons/netgrip-button.sh
var btnRunnerScript []byte

// btnMarker is in every file the feature installs: a file without it is
// never NetGrip's.
const btnMarker = "netgrip-managed-button"

// Paths; vars so tests can redirect them.
var (
	btnRunnerPath = "/usr/libexec/netgrip-button"
	btnRcDir      = "/etc/rc.button"
	btnRomRcDir   = "/rom/etc/rc.button" // the firmware image's own copy
	btnRcdDir     = "/etc/rc.d"
	btnEtcDir     = "/etc/netgrip/buttons"
	btnStateDir   = "/tmp/netgrip-buttons"
	btnHookPath   = "/etc/hotplug.d/button/00-netgrip"
	btnInitPath   = "/etc/init.d/netgrip-buttons"
	btnLedsDir    = "/sys/class/leds"
	btnHotplugCfg = "/etc/hotplug.json"               // procd's hotplug rules
	btnModuleDir  = "/sys/module/gpio_button_hotplug" // the kernel module that reports presses
	btnLookPath   = exec.LookPath
	btnDTDir      = "/sys/firmware/devicetree/base"

	// btnInitEnableFn turns the boot script on or off (rc.common's
	// enable/disable make or remove its /etc/rc.d link).
	btnInitEnableFn = func(enable bool) error {
		verb := "disable"
		if enable {
			verb = "enable"
		}
		out, err := exec.Command(btnInitPath, verb).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %v (%s)", btnInitPath, verb, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	btnNotifyFn  = notifyAll
	btnChannelFn = anyChannelEnabled
	btnNow       = time.Now
)

const (
	btnMaxActions  = 16
	btnMaxPresses  = 3
	btnHoldMin     = 2  // the runner's HOLD_MIN: shorter is a press
	btnHoldMax     = 30 // longer is not something anyone holds on purpose
	btnMinutesMax  = 1440
	btnListenFor   = 5 * time.Minute
	btnEventsShown = 30
)

// The actions a button can run.
var btnActionKinds = map[string]bool{
	"wifi_toggle":      true, // one Wi-Fi network on/off, optionally for a while
	"firewall_restart": true,
	"access_restart":   true, // SSH, LuCI's web server, the NetGrip panel
}

var (
	reBtnName   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	reBtnIface  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	reBtnLED    = regexp.MustCompile(`^[A-Za-z0-9_:.+-]{1,64}$`)
	reBtnSeenGe = regexp.MustCompile(`SEEN"?\s+-(ge|gt)\s+([0-9]+)`)
	reBtnQuoted = regexp.MustCompile(`'([^']*)'`)
)

// ButtonAction is one assigned action. A press is Count presses in a row
// (1 to 3); a hold is keeping the button down at least Seconds.
type ButtonAction struct {
	Button  string `json:"button"`
	Trigger string `json:"trigger"` // "press" | "hold"
	Count   int    `json:"count,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
	Action  string `json:"action"`
	// Iface: the wireless section (wifi_toggle). Minutes: how long the
	// toggle lasts before it goes back; 0 keeps it.
	Iface   string `json:"iface,omitempty"`
	Minutes int    `json:"minutes,omitempty"`
}

// ButtonsConfig is everything the user sets.
type ButtonsConfig struct {
	Actions []ButtonAction `json:"actions"`
	LED     string         `json:"led"` // blinks when an action runs; "" for none
}

// ButtonInfo is one button the panel can offer.
type ButtonInfo struct {
	Name string `json:"name"`
	// Board: the board's description lists it. Pressed: it was pressed
	// since the router started (only those are certain to exist).
	Board   bool `json:"board,omitempty"`
	Pressed bool `json:"pressed,omitempty"`
	// Stock: what its original script does ("reset", "wps", "rfkill",
	// "power", "reboot", "custom", or "" for no script).
	Stock string `json:"stock,omitempty"`
	// Reserved: holding it this long or longer always does what the
	// original does (the factory reset); 0 when nothing is reserved.
	Reserved int  `json:"reserved,omitempty"`
	Managed  bool `json:"managed,omitempty"` // NetGrip's wrapper is in place
	// Switch: it reports a position (a slider), so it cannot run actions.
	Switch bool `json:"switch,omitempty"`
}

// ButtonNetwork is a Wi-Fi network a button can turn on or off.
type ButtonNetwork struct {
	Section  string `json:"section"`
	SSID     string `json:"ssid"`
	Disabled bool   `json:"disabled"`
	// Until: a button turned it on or off until then (Unix seconds); it
	// goes back afterwards. Kept: a button toggled it without a time.
	Until int64 `json:"until,omitempty"`
}

// ButtonEvent is one action the runner ran.
type ButtonEvent struct {
	At      int64  `json:"at"`
	Button  string `json:"button"`
	Pattern string `json:"pattern"` // press1..3, holdN, timer
	Action  string `json:"action"`
	Detail  string `json:"detail"`
	Result  string `json:"result"`
	Text    string `json:"text"`
}

// ButtonPress is the last button event the router saw.
type ButtonPress struct {
	At     int64  `json:"at"`
	Button string `json:"button"`
	Action string `json:"action"`
	Seen   int    `json:"seen"`
	Switch bool   `json:"switch,omitempty"`
}

// ButtonRequirement is one thing the feature uses on the router, and the
// package that provides it. A missing required one turns the feature off;
// a missing optional one only weakens what it says in For.
type ButtonRequirement struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Required bool   `json:"required"`
	Package  string `json:"package"`
	// For: "buttons" (the feature itself), "wifi" (the Wi-Fi action),
	// "locking" (two actions at once), "detach" (actions run apart from
	// the press), "check" (noticing a config saved meanwhile).
	For string `json:"for"`
}

// ButtonsProbe is the panel's view.
type ButtonsProbe struct {
	Available    bool                `json:"available"`
	Requirements []ButtonRequirement `json:"requirements"`
	Buttons     []ButtonInfo    `json:"buttons"`
	Config      ButtonsConfig   `json:"config"`
	LEDs        []string        `json:"leds"`
	Networks    []ButtonNetwork `json:"networks"`
	Events      []ButtonEvent   `json:"events"`
	LastPress   *ButtonPress    `json:"last_press,omitempty"`
	ListenUntil int64           `json:"listen_until,omitempty"`
	Notify      bool            `json:"notify"`
}

var (
	btnMu          sync.Mutex
	btnListenUntil time.Time
	btnListenTimer *time.Timer
)

func btnHave(cmds ...string) bool {
	for _, c := range cmds {
		if _, err := btnLookPath(c); err == nil {
			return true
		}
	}
	return false
}

// btnRequirements checks what the feature uses. Nothing here is installed
// by NetGrip: on a router without one, the panel names the package.
func btnRequirements() []ButtonRequirement {
	st, err := os.Stat(btnRcDir)
	rcdir := err == nil && st.IsDir()
	rules, _ := os.ReadFile(btnHotplugCfg)
	procd := rcdir && strings.Contains(string(rules), "rc.button")
	// The module, or proof it works: a press already reached the runner.
	_, err = os.Stat(btnModuleDir)
	kmod := err == nil
	if !kmod {
		seen, _ := filepath.Glob(filepath.Join(btnStateDir, "seen.*"))
		kmod = len(seen) > 0
	}
	return []ButtonRequirement{
		{Name: "procd button events", OK: procd, Required: true, Package: "procd, base-files", For: "buttons"},
		{Name: "gpio-button-hotplug", OK: kmod, Required: true, Package: "kmod-gpio-button-hotplug", For: "buttons"},
		{Name: "awk", OK: btnHave("awk"), Required: true, Package: "busybox (awk) or gawk", For: "buttons"},
		{Name: "uci", OK: btnHave("uci"), Required: true, Package: "uci", For: "buttons"},
		{Name: "wifi", OK: btnHave("wifi"), Package: "wifi-scripts (base-files before 24.10)", For: "wifi"},
		{Name: "flock", OK: btnHave("flock", "lock"), Package: "busybox (flock or lock)", For: "locking"},
		{Name: "setsid", OK: btnHave("setsid"), Package: "busybox (setsid)", For: "detach"},
		{Name: "md5sum", OK: btnHave("md5sum", "sha256sum"), Package: "busybox (md5sum)", For: "check"},
	}
}

// btnAvailable: everything the feature needs is on this router.
func btnAvailable() bool {
	for _, r := range btnRequirements() {
		if r.Required && !r.OK {
			return false
		}
	}
	return true
}

// btnUnavailable says what is missing.
func btnUnavailable() error {
	var miss []string
	for _, r := range btnRequirements() {
		if r.Required && !r.OK {
			miss = append(miss, r.Name+" ("+r.Package+")")
		}
	}
	return fmt.Errorf("router buttons need: %s", strings.Join(miss, ", "))
}

// --- configuration ---------------------------------------------------------

// btnLine is the runner's form of one action:
// <button> <press|hold> <count|seconds> <action> <iface|-> <minutes>.
func btnLine(a ButtonAction) string {
	n := a.Count
	if a.Trigger == "hold" {
		n = a.Seconds
	}
	iface := a.Iface
	if iface == "" {
		iface = "-"
	}
	return fmt.Sprintf("%s %s %d %s %s %d", a.Button, a.Trigger, n, a.Action, iface, a.Minutes)
}

func btnParseLine(s string) (ButtonAction, bool) {
	f := strings.Fields(s)
	if len(f) != 6 {
		return ButtonAction{}, false
	}
	n, err1 := strconv.Atoi(f[2])
	m, err2 := strconv.Atoi(f[5])
	if err1 != nil || err2 != nil {
		return ButtonAction{}, false
	}
	a := ButtonAction{Button: f[0], Trigger: f[1], Action: f[3], Minutes: m}
	if f[4] != "-" {
		a.Iface = f[4]
	}
	if a.Trigger == "hold" {
		a.Seconds = n
	} else {
		a.Count = n
	}
	return a, true
}

// loadButtonsConfig reads netgrip.buttons; actions that no longer pass the
// checks (edited by hand) are left out.
func loadButtonsConfig() ButtonsConfig {
	cfg := ButtonsConfig{Actions: []ButtonAction{}}
	if !uciSectionExists("netgrip.buttons") {
		return cfg
	}
	cfg.LED = uciGet("netgrip.buttons.led")
	// show, not get: get joins a list's items with spaces, and each item
	// has spaces of its own; show quotes each one.
	out, err := uciExec("-q", "show", "netgrip.buttons.action")
	if err != nil {
		return cfg
	}
	for _, item := range reBtnQuoted.FindAllStringSubmatch(string(out), -1) {
		if a, ok := btnParseLine(item[1]); ok {
			cfg.Actions = append(cfg.Actions, a)
		}
	}
	return cfg
}

// validateButtons checks a configuration against the router. reserved
// gives each button's reserved hold (see btnReserved).
func validateButtons(cfg *ButtonsConfig, reserved func(string) int) error {
	if len(cfg.Actions) > btnMaxActions {
		return fmt.Errorf("at most %d actions", btnMaxActions)
	}
	seen := map[string]bool{}
	for i := range cfg.Actions {
		a := &cfg.Actions[i]
		a.Button = strings.TrimSpace(a.Button)
		if !reBtnName.MatchString(a.Button) || a.Button == "failsafe" {
			return fmt.Errorf("%q is not a button name", a.Button)
		}
		if btnIsSwitch(a.Button) {
			return fmt.Errorf("%s is a switch, not a button: it cannot run actions", a.Button)
		}
		switch a.Trigger {
		case "press":
			a.Seconds = 0
			if a.Count < 1 || a.Count > btnMaxPresses {
				return fmt.Errorf("%s: presses must be 1 to %d", a.Button, btnMaxPresses)
			}
		case "hold":
			a.Count = 0
			if a.Seconds < btnHoldMin || a.Seconds > btnHoldMax {
				return fmt.Errorf("%s: a hold must be %d to %d seconds", a.Button, btnHoldMin, btnHoldMax)
			}
			if r := reserved(a.Button); r > 0 && a.Seconds >= r {
				return fmt.Errorf("%s: holding it %d seconds or more stays with what the button does on its own (resetting the router); choose a shorter hold", a.Button, r)
			}
		default:
			return fmt.Errorf("%s: unknown trigger %q", a.Button, a.Trigger)
		}
		if !btnActionKinds[a.Action] {
			return fmt.Errorf("%s: unknown action %q", a.Button, a.Action)
		}
		if a.Action == "wifi_toggle" {
			if !btnHave("wifi") {
				return fmt.Errorf("%s: switching Wi-Fi needs the wifi command (wifi-scripts)", a.Button)
			}
			if !reBtnIface.MatchString(a.Iface) || uciGet("wireless."+a.Iface) != "wifi-iface" {
				return fmt.Errorf("%s: choose a Wi-Fi network", a.Button)
			}
			if a.Minutes < 0 || a.Minutes > btnMinutesMax {
				return fmt.Errorf("%s: minutes must be 0 to %d", a.Button, btnMinutesMax)
			}
		} else {
			a.Iface, a.Minutes = "", 0
		}
		key := fmt.Sprintf("%s %s %d", a.Button, a.Trigger, a.Count+a.Seconds)
		if seen[key] {
			return fmt.Errorf("%s: the same press is assigned twice", a.Button)
		}
		seen[key] = true
	}
	cfg.LED = strings.TrimSpace(cfg.LED)
	if cfg.LED != "" {
		if !reBtnLED.MatchString(cfg.LED) {
			return fmt.Errorf("%q is not an LED", cfg.LED)
		}
		if _, err := os.Stat(filepath.Join(btnLedsDir, cfg.LED, "trigger")); err != nil {
			return fmt.Errorf("this router has no LED %q", cfg.LED)
		}
	}
	sort.SliceStable(cfg.Actions, func(i, j int) bool {
		a, b := cfg.Actions[i], cfg.Actions[j]
		if a.Button != b.Button {
			return a.Button < b.Button
		}
		if a.Trigger != b.Trigger {
			return a.Trigger > b.Trigger // presses first
		}
		return a.Count+a.Seconds < b.Count+b.Seconds
	})
	return nil
}

// SetButtons saves the configuration and puts it in place on the router.
func SetButtons(cfg ButtonsConfig) (ButtonsProbe, error) {
	btnMu.Lock()
	defer btnMu.Unlock()
	if !btnAvailable() {
		return btnProbeLocked(), btnUnavailable()
	}
	if cfg.Actions == nil {
		cfg.Actions = []ButtonAction{}
	}
	if err := validateButtons(&cfg, btnReserved); err != nil {
		return btnProbeLocked(), err
	}
	if err := EnsureNetgripSection("buttons", "buttons"); err != nil {
		return btnProbeLocked(), err
	}
	// uci_delete of a missing option fails the batch: only delete what is
	// there.
	var ops []executor.Op
	if uciGet("netgrip.buttons.action") != "" {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"netgrip.buttons.action"}})
	}
	if uciGet("netgrip.buttons.led") != "" {
		ops = append(ops, executor.Op{Kind: "uci_delete", Args: []string{"netgrip.buttons.led"}})
	}
	for _, a := range cfg.Actions {
		ops = append(ops, executor.Op{Kind: "uci_add_list", Args: []string{"netgrip.buttons.action", btnLine(a)}})
	}
	if cfg.LED != "" {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{"netgrip.buttons.led", cfg.LED}})
	}
	if len(ops) > 0 {
		if err := applyNetgripConfig(ops); err != nil {
			return btnProbeLocked(), err
		}
	}
	if err := btnApplyLocked(cfg); err != nil {
		return btnProbeLocked(), err
	}
	btnStartWatch(len(cfg.Actions) > 0)
	return btnProbeLocked(), nil
}

// --- what the router has ---------------------------------------------------

// gpio-button-hotplug's names for the key codes boards give their buttons
// (the kernel module's button_map): the name procd passes as BUTTON.
var btnKeyNames = map[uint32]string{
	0x100: "BTN_0", 0x101: "BTN_1", 0x102: "BTN_2", 0x103: "BTN_3", 0x104: "BTN_4",
	0x105: "BTN_5", 0x106: "BTN_6", 0x107: "BTN_7", 0x108: "BTN_8", 0x109: "BTN_9",
	116:   "power",
	0x164: "reboot", // KEY_POWER2
	0x198: "reset",  // KEY_RESTART
	247:   "rfkill",
	238:   "wlan",
	0x211: "wps", // KEY_WPS_BUTTON
	171:   "config",
	246:   "wwan", // KEY_WIMAX
}

// btnBoardButtons lists the buttons the board's device tree declares
// (gpio-keys and gpio-keys-polled nodes). Boards without a device tree
// (x86) list none: the panel then learns them from a press.
func btnBoardButtons() []string {
	var out []string
	seen := map[string]bool{}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			node := filepath.Join(dir, e.Name())
			if compat, err := os.ReadFile(filepath.Join(node, "compatible")); err == nil && strings.Contains(string(compat), "gpio-keys") {
				keys, _ := os.ReadDir(node)
				for _, k := range keys {
					raw, err := os.ReadFile(filepath.Join(node, k.Name(), "linux,code"))
					if err != nil || len(raw) != 4 {
						continue
					}
					// A switch (EV_SW, 5) reports a position, not a press.
					if it, err := os.ReadFile(filepath.Join(node, k.Name(), "linux,input-type")); err == nil && len(it) == 4 && binary.BigEndian.Uint32(it) == 5 {
						continue
					}
					if name, ok := btnKeyNames[binary.BigEndian.Uint32(raw)]; ok && !seen[name] {
						seen[name] = true
						out = append(out, name)
					}
				}
				continue
			}
			if depth < 1 {
				walk(node, depth+1)
			}
		}
	}
	walk(btnDTDir, 0)
	sort.Strings(out)
	return out
}

// btnOriginal is the button's original script: the script itself when it
// is not NetGrip's, else the copy NetGrip keeps, else (that copy lost) the
// firmware image's own.
func btnOriginal(name string) ([]byte, bool) {
	if data, err := os.ReadFile(filepath.Join(btnRcDir, name)); err == nil && !btnIsOurs(data) {
		return data, true
	}
	if btnHadNone(name) {
		return nil, false
	}
	for _, p := range []string{filepath.Join(btnEtcDir, "orig", name), filepath.Join(btnRomRcDir, name)} {
		if data, err := os.ReadFile(p); err == nil && !btnIsOurs(data) {
			return data, true
		}
	}
	return nil, false
}

// btnHadNone: the button had no script when NetGrip took it over. One
// removed on purpose must not come back from the firmware image.
func btnHadNone(name string) bool {
	_, err := os.Stat(filepath.Join(btnEtcDir, "orig", name+".none"))
	return err == nil
}

func btnIsOurs(data []byte) bool {
	return strings.Contains(string(data), btnMarker)
}

// btnReserved: how long a hold of this button always goes to its original
// script. A script that resets the router to factory settings does it on
// a hold ("$SEEN" -ge N): from N on, nothing else may take the button.
func btnReserved(name string) int {
	data, ok := btnOriginal(name)
	if !ok {
		return 0
	}
	return btnReservedFor(name, string(data))
}

// btnReservedFor is btnReservedIn, with one more precaution: a script for
// the button the kernel calls "reset" (KEY_RESTART) that does not read as
// OpenWrt's may still reset the router in a way not recognised here (a
// vendor tool), so no hold is offered on it.
func btnReservedFor(name, script string) int {
	r := btnReservedIn(script)
	if r == 0 && name == "reset" && btnStock(script) == "custom" {
		return btnHoldMin
	}
	return r
}

func btnReservedIn(script string) int {
	if !strings.Contains(script, "factoryreset") && !strings.Contains(script, "jffs2reset") && !strings.Contains(script, "firstboot") {
		return 0
	}
	min := 0
	for _, m := range reBtnSeenGe.FindAllStringSubmatch(script, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		if m[1] == "gt" {
			n++ // more than n seconds: from n+1 on, in whole seconds
		}
		if n > 0 && (min == 0 || n < min) {
			min = n
		}
	}
	if min == 0 {
		// It resets the router, but when is unclear: no hold is offered.
		return btnHoldMin
	}
	return min
}

// btnStock says what the original script does, for the panel.
func btnStock(script string) string {
	switch {
	case script == "":
		return ""
	case strings.Contains(script, "factoryreset") || strings.Contains(script, "jffs2reset") || strings.Contains(script, "firstboot"):
		return "reset"
	case strings.Contains(script, "rc.wps"):
		return "wps"
	case strings.Contains(script, "wifi_rfkill"):
		return "rfkill"
	case strings.Contains(script, "poweroff"):
		return "power"
	case strings.Contains(script, "reboot"):
		return "reboot"
	}
	return "custom"
}

// btnButtonsLocked lists the buttons worth offering: the board's, those
// pressed since boot, and those with actions. Scripts in /etc/rc.button
// alone prove nothing (images ship "power" and "reboot" for every board).
func btnButtonsLocked(cfg ButtonsConfig) []ButtonInfo {
	byName := map[string]*ButtonInfo{}
	get := func(n string) *ButtonInfo {
		if b, ok := byName[n]; ok {
			return b
		}
		b := &ButtonInfo{Name: n}
		byName[n] = b
		return b
	}
	for _, n := range btnBoardButtons() {
		get(n).Board = true
	}
	if entries, err := os.ReadDir(btnStateDir); err == nil {
		for _, e := range entries {
			if n, ok := strings.CutPrefix(e.Name(), "seen."); ok && reBtnName.MatchString(n) && n != "failsafe" {
				b := get(n)
				b.Pressed = true
				b.Switch = btnIsSwitch(n)
			}
		}
	}
	for _, a := range cfg.Actions {
		get(a.Button)
	}
	out := make([]ButtonInfo, 0, len(byName))
	for _, b := range byName {
		if data, ok := btnOriginal(b.Name); ok {
			b.Stock = btnStock(string(data))
			b.Reserved = btnReservedFor(b.Name, string(data))
		}
		if data, err := os.ReadFile(filepath.Join(btnRcDir, b.Name)); err == nil && btnIsOurs(data) {
			b.Managed = true
		}
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// btnIsSwitch: the button reported a position when it was last pressed
// (the runner records procd's TYPE): a slider, which cannot run actions.
func btnIsSwitch(name string) bool {
	data, err := os.ReadFile(filepath.Join(btnStateDir, "seen."+name))
	t := strings.TrimSpace(string(data))
	return err == nil && t != "" && t != "-"
}

func btnLEDs() []string {
	out := []string{}
	entries, err := os.ReadDir(btnLedsDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if reBtnLED.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// btnNetworks: the access points a button can turn on or off. Only named
// sections: an unnamed one's index changes when networks are added.
func btnNetworks() []ButtonNetwork {
	out := []ButtonNetwork{}
	for _, sec := range wifiIfaceSections() {
		if !reBtnIface.MatchString(sec) {
			continue
		}
		if mode := uciGet("wireless." + sec + ".mode"); mode != "" && mode != "ap" {
			continue
		}
		n := ButtonNetwork{
			Section:  sec,
			SSID:     uciGet("wireless." + sec + ".ssid"),
			Disabled: uciGet("wireless."+sec+".disabled") == "1",
		}
		if h, ok := btnReadHold(sec); ok && h.until > 0 {
			n.Until = h.until
		}
		out = append(out, n)
	}
	return out
}

// --- putting it in place ---------------------------------------------------

func btnWrapper(name string, reserved int) string {
	orig := filepath.Join(btnEtcDir, "orig", name)
	rom := filepath.Join(btnRomRcDir, name)
	return fmt.Sprintf(`#!/bin/sh
# %s
# NetGrip runs the actions assigned to this button and hands every other
# press to the original script, kept in %s.
# Removing the button's actions in NetGrip puts the original back.
[ -x %s ] && exec %s rc '%s' %d
# Without NetGrip's runner: the original, else the firmware image's (not
# when the button had no script of its own).
[ -f %s.none ] && exit 0
for o in %s %s; do
	[ -f "$o" ] || continue
	grep -q %s "$o" && continue
	[ -x "$o" ] && exec "$o"
	exec /bin/sh "$o"
done
exit 0
`, btnMarker, orig, btnRunnerPath, btnRunnerPath, name, reserved, orig, orig, rom, btnMarker)
}

func btnHookScript() string {
	return fmt.Sprintf(`# %s
# Tells NetGrip which button was pressed, so its panel can offer it.
[ -x %s ] && %s seen
`, btnMarker, btnRunnerPath, btnRunnerPath)
}

func btnInitScript() string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# %s
# At boot, before networking: a Wi-Fi network a router button turned on or
# off for a limited time goes back as it was when the router restarted
# before that time was up. Installed by NetGrip.

START=15

boot() {
	[ -x %s ] && %s boot
	return 0
}

start() {
	return 0
}
`, btnMarker, btnRunnerPath, btnRunnerPath)
}

// btnWrite writes a file atomically and durably, only when its content or
// mode differ (flash wears).
func btnWrite(path string, data []byte, mode os.FileMode) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(data) {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() == mode {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".netgrip-tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// btnEnsureWrapper puts NetGrip's wrapper in place of a button's script,
// keeping the original aside. A script that is not NetGrip's (a new one an
// upgrade wrote) becomes the kept original.
func btnEnsureWrapper(name string) error {
	path := filepath.Join(btnRcDir, name)
	orig := filepath.Join(btnEtcDir, "orig", name)
	cur, err := os.ReadFile(path)
	switch {
	case err == nil && !btnIsOurs(cur):
		if err := btnWrite(orig, cur, 0o755); err != nil {
			return fmt.Errorf("keep the original %s script: %w", name, err)
		}
		_ = os.Remove(orig + ".none")
	case os.IsNotExist(err):
		// No script: the button did nothing, and must go on doing
		// nothing for presses not assigned (not the firmware's script).
		// Any kept copy is from an older system and must not come back.
		_ = os.Remove(orig)
		if err := btnWrite(orig+".none", []byte("# "+btnMarker+": "+name+" had no script\n"), 0o644); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	return btnWrite(path, []byte(btnWrapper(name, btnReserved(name))), 0o755)
}

// btnRestore puts a button's original script back (or removes the
// wrapper of a button that had none).
func btnRestore(name string) error {
	path := filepath.Join(btnRcDir, name)
	orig := filepath.Join(btnEtcDir, "orig", name)
	if btnHadNone(name) {
		_ = os.Remove(orig + ".none")
		if cur, err := os.ReadFile(path); err == nil && btnIsOurs(cur) {
			return os.Remove(path)
		}
		return nil
	}
	data, err := os.ReadFile(orig)
	if err == nil && !btnIsOurs(data) {
		if err := btnWrite(path, data, 0o755); err != nil {
			return err
		}
		return os.Remove(orig)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// The kept copy is gone: the firmware image's script, if it has one.
	if data, err := os.ReadFile(filepath.Join(btnRomRcDir, name)); err == nil && !btnIsOurs(data) {
		return btnWrite(path, data, 0o755)
	}
	if cur, err := os.ReadFile(path); err == nil && btnIsOurs(cur) {
		return os.Remove(path)
	}
	return nil
}

// btnTimedPending: a toggle with a time is still running (or the router
// restarted during one): the boot script must stay until it is over.
func btnTimedPending() bool {
	entries, err := os.ReadDir(filepath.Join(btnEtcDir, "timed"))
	return err == nil && len(entries) > 0
}

// btnApplyLocked makes the router match cfg: the runner, its copy of the
// actions, a wrapper for each button with actions and the original back
// for every other. With nothing assigned, nothing of the feature stays
// beyond what a running timed toggle still needs.
func btnApplyLocked(cfg ButtonsConfig) error {
	used := map[string]bool{}
	for _, a := range cfg.Actions {
		used[a.Button] = true
	}
	listening := btnNow().Before(btnListenUntil)
	timed := btnTimedPending()
	need := len(used) > 0 || listening || timed

	var errs []string
	if need {
		if err := btnWrite(btnRunnerPath, btnRunnerScript, 0o755); err != nil {
			return fmt.Errorf("install %s: %w", btnRunnerPath, err)
		}
		var b strings.Builder
		b.WriteString("# " + btnMarker + ": written by NetGrip from netgrip.buttons; edits are overwritten\n")
		for _, a := range cfg.Actions {
			b.WriteString(btnLine(a) + "\n")
		}
		if err := btnWrite(filepath.Join(btnEtcDir, "actions"), []byte(b.String()), 0o644); err != nil {
			return err
		}
		ledPath := filepath.Join(btnEtcDir, "led")
		if cfg.LED != "" {
			if err := btnWrite(ledPath, []byte(cfg.LED+"\n"), 0o644); err != nil {
				return err
			}
		} else {
			_ = os.Remove(ledPath)
		}
		_ = os.MkdirAll(btnStateDir, 0o755)
	}
	for name := range used {
		if err := btnEnsureWrapper(name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if entries, err := os.ReadDir(btnRcDir); err == nil {
		for _, e := range entries {
			if used[e.Name()] {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(btnRcDir, e.Name())); err == nil && btnIsOurs(data) {
				if err := btnRestore(e.Name()); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
	}
	// The hook only tells the panel which button was pressed.
	if len(used) > 0 || listening {
		if err := btnWrite(btnHookPath, []byte(btnHookScript()), 0o644); err != nil {
			errs = append(errs, err.Error())
		}
	} else {
		btnRemoveOurs(btnHookPath)
		_ = os.Remove(filepath.Dir(btnHookPath)) // only if empty
	}
	if len(used) > 0 || timed {
		if err := btnWrite(btnInitPath, []byte(btnInitScript()), 0o755); err != nil {
			errs = append(errs, err.Error())
		} else if !btnInitLinked() {
			// Only when its link is missing: enable rewrites it on flash.
			if err := btnInitEnableFn(true); err != nil {
				errs = append(errs, err.Error())
			}
		}
	} else if data, err := os.ReadFile(btnInitPath); err == nil && btnIsOurs(data) {
		if btnInitLinked() {
			_ = btnInitEnableFn(false)
		}
		_ = os.Remove(btnInitPath)
	}
	if !need {
		btnRemoveOurs(btnRunnerPath)
		_ = os.Remove(filepath.Join(btnEtcDir, "actions"))
		_ = os.Remove(filepath.Join(btnEtcDir, "led"))
		if names, _ := filepath.Glob(filepath.Join(btnEtcDir, "orig", "*.none")); len(names) > 0 {
			for _, n := range names {
				_ = os.Remove(n)
			}
		}
		_ = os.Remove(filepath.Join(btnEtcDir, "orig"))
		_ = os.Remove(btnEtcDir)
	}
	if len(errs) > 0 {
		return fmt.Errorf("buttons: %s", strings.Join(errs, "; "))
	}
	return nil
}

// btnInitLinked: the boot script is enabled (rc.common's S<NN> link).
func btnInitLinked() bool {
	links, _ := filepath.Glob(filepath.Join(btnRcdDir, "S*"+filepath.Base(btnInitPath)))
	return len(links) > 0
}

// btnRemoveOurs removes a file only if NetGrip wrote it.
func btnRemoveOurs(path string) {
	if data, err := os.ReadFile(path); err == nil && btnIsOurs(data) {
		_ = os.Remove(path)
	}
}

// --- listening for a press -------------------------------------------------

// ListenButtons installs the hook that records presses for a few minutes,
// so the panel can learn a button the board description does not list.
func ListenButtons() (ButtonsProbe, error) {
	btnMu.Lock()
	defer btnMu.Unlock()
	if !btnAvailable() {
		return btnProbeLocked(), btnUnavailable()
	}
	btnListenUntil = btnNow().Add(btnListenFor)
	err := btnApplyLocked(loadButtonsConfig())
	if btnListenTimer != nil {
		btnListenTimer.Stop()
	}
	btnListenTimer = time.AfterFunc(btnListenFor+time.Second, func() {
		btnMu.Lock()
		defer btnMu.Unlock()
		if err := btnApplyLocked(loadButtonsConfig()); err != nil {
			log.Printf("netgrip: buttons: %v", err)
		}
	})
	return btnProbeLocked(), err
}

// --- the panel's view ------------------------------------------------------

// ButtonsListen is what the panel polls while it waits for a press: cheap
// (two small files), unlike the full view.
type ButtonsListen struct {
	LastPress   *ButtonPress `json:"last_press,omitempty"`
	ListenUntil int64        `json:"listen_until,omitempty"`
}

func ProbeButtonsLast() ButtonsListen {
	btnMu.Lock()
	until := btnListenUntil
	btnMu.Unlock()
	out := ButtonsListen{LastPress: btnLastPress()}
	if btnNow().Before(until) {
		out.ListenUntil = until.Unix()
	}
	return out
}

// ProbeButtons is the panel's view. It also repairs what an upgrade
// undid (a button script replaced by a package), which costs nothing when
// everything is in place.
func ProbeButtons() ButtonsProbe {
	btnMu.Lock()
	defer btnMu.Unlock()
	cfg := loadButtonsConfig()
	if btnAvailable() && (len(cfg.Actions) > 0 || btnTimedPending()) {
		if err := btnApplyLocked(cfg); err != nil {
			log.Printf("netgrip: buttons: %v", err)
		}
	}
	return btnProbeLocked()
}

func btnProbeLocked() ButtonsProbe {
	cfg := loadButtonsConfig()
	p := ButtonsProbe{
		Requirements: btnRequirements(),
		Config:    cfg,
		LEDs:      btnLEDs(),
		Networks:  btnNetworks(),
		Events:    []ButtonEvent{},
		Notify:    btnChannelFn(),
	}
	p.Available = true
	for _, r := range p.Requirements {
		if r.Required && !r.OK {
			p.Available = false
		}
	}
	p.Buttons = btnButtonsLocked(cfg)
	ssid := map[string]string{}
	for _, n := range p.Networks {
		ssid[n.Section] = n.SSID
	}
	events := btnReadEvents()
	for i := len(events) - 1; i >= 0 && len(p.Events) < btnEventsShown; i-- {
		e := events[i].ev
		e.Text = btnEventText(e, ssid)
		p.Events = append(p.Events, e)
	}
	p.LastPress = btnLastPress()
	if btnNow().Before(btnListenUntil) {
		p.ListenUntil = btnListenUntil.Unix()
	}
	return p
}

func btnLastPress() *ButtonPress {
	data, err := os.ReadFile(filepath.Join(btnStateDir, "last"))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(data))
	if len(f) < 5 || !reBtnName.MatchString(f[1]) {
		return nil
	}
	at, _ := strconv.ParseInt(f[0], 10, 64)
	seen, _ := strconv.Atoi(f[3])
	return &ButtonPress{At: at, Button: f[1], Action: f[2], Seen: seen, Switch: f[4] != "-"}
}

// --- events and notifications ----------------------------------------------

type btnEventRec struct {
	id int64 // the router's uptime in hundredths: increasing since boot
	ev ButtonEvent
}

func btnReadEvents() []btnEventRec {
	data, err := os.ReadFile(filepath.Join(btnStateDir, "events"))
	if err != nil {
		return nil
	}
	var out []btnEventRec
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			continue
		}
		id, err1 := strconv.ParseInt(f[0], 10, 64)
		at, err2 := strconv.ParseInt(f[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, btnEventRec{id: id, ev: ButtonEvent{At: at, Button: f[2], Pattern: f[3], Action: f[4], Detail: f[5], Result: f[6]}})
	}
	return out
}

func btnPatternText(button, p string) string {
	switch {
	case p == "press1":
		return fmt.Sprintf("Button %s pressed", button)
	case p == "press2":
		return fmt.Sprintf("Button %s pressed twice", button)
	case strings.HasPrefix(p, "press"):
		return fmt.Sprintf("Button %s pressed %s times", button, strings.TrimPrefix(p, "press"))
	case strings.HasPrefix(p, "hold"):
		return fmt.Sprintf("Button %s held %s s", button, strings.TrimPrefix(p, "hold"))
	}
	return ""
}

// btnEventText says what happened, in one sentence.
func btnEventText(e ButtonEvent, ssid map[string]string) string {
	failed := strings.HasPrefix(e.Result, "failed")
	var what string
	switch e.Action {
	case "wifi_toggle":
		f := strings.Fields(e.Detail)
		name, state, minutes := e.Detail, "", 0
		if len(f) >= 2 {
			name, state = f[0], f[1]
			if s := ssid[f[0]]; s != "" {
				name = s
			}
		}
		if len(f) >= 3 {
			minutes, _ = strconv.Atoi(f[2])
		}
		switch {
		case failed:
			what = fmt.Sprintf("turning Wi-Fi %q %s failed (%s)", name, state, e.Result)
		case e.Result == "reverted" && e.Button == "boot":
			what = fmt.Sprintf("Wi-Fi %q is %s again: the router restarted before its time was up", name, state)
		case e.Result == "reverted":
			what = fmt.Sprintf("Wi-Fi %q is %s again after %d min", name, state, minutes)
		case e.Result == "ended":
			what = fmt.Sprintf("Wi-Fi %q is %s again (ended early)", name, state)
		case minutes > 0:
			what = fmt.Sprintf("Wi-Fi %q turned %s for %d min", name, state, minutes)
		default:
			what = fmt.Sprintf("Wi-Fi %q turned %s", name, state)
		}
	case "firewall_restart":
		what = "firewall restarted"
		if failed {
			what = "restarting the firewall failed"
		}
	case "access_restart":
		what = "restarted " + strings.ReplaceAll(e.Detail, ",", ", ")
		if e.Detail == "-" {
			what = "no access service to restart"
		}
		if failed {
			what += " (" + e.Result + ")"
		}
	default:
		what = e.Action + " " + e.Result
	}
	if p := btnPatternText(e.Button, e.Pattern); p != "" {
		return p + ": " + what
	}
	return strings.ToUpper(what[:1]) + what[1:]
}

var (
	btnWatchOnce sync.Once
	btnNotifyMu  sync.Mutex
)

// btnNotifyNew sends one notification per action the runner logged since
// the last one sent. The mark lives with the log, so a NetGrip restart (an
// action may restart it) neither repeats nor loses one; both go at reboot.
func btnNotifyNew() {
	btnNotifyMu.Lock()
	defer btnNotifyMu.Unlock()
	markPath := filepath.Join(btnStateDir, "notified")
	var mark int64
	if data, err := os.ReadFile(markPath); err == nil {
		mark, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}
	events := btnReadEvents()
	var fresh []btnEventRec
	for _, r := range events {
		if r.id > mark {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 {
		return
	}
	_ = writeFileAtomic(markPath, []byte(strconv.FormatInt(fresh[len(fresh)-1].id, 10)+"\n"))
	if !btnChannelFn() {
		return
	}
	ssid := map[string]string{}
	for _, n := range btnNetworks() {
		ssid[n.Section] = n.SSID
	}
	for _, r := range fresh {
		text := btnEventText(r.ev, ssid)
		btnNotifyFn("NetGrip",
			fmt.Sprintf("🔘 <b>NetGrip</b>\n%s", htmlEsc(text)),
			fmt.Sprintf("🔘 NetGrip\n%s", text),
			false)
	}
}

// btnStartWatch starts, once, the watcher that notifies what the runner
// ran. It sleeps in the kernel until the runner writes its log.
func btnStartWatch(want bool) {
	if !want {
		return
	}
	btnWatchOnce.Do(func() {
		go btnWatch()
	})
}

// StartButtons repairs the router's button setup at start (a sysupgrade
// or a package upgrade replaces button scripts) and starts the watcher
// when actions are assigned. Without actions it only cleans up.
func StartButtons() {
	if !btnAvailable() {
		return
	}
	btnMu.Lock()
	cfg := loadButtonsConfig()
	if err := btnApplyLocked(cfg); err != nil {
		log.Printf("netgrip: buttons: %v", err)
	}
	btnMu.Unlock()
	btnStartWatch(len(cfg.Actions) > 0 || btnTimedPending())
}

// --- the Wi-Fi schedule ----------------------------------------------------

type btnHold struct {
	until int64 // 0: until the schedule changes
	token string
}

func btnReadHold(section string) (btnHold, bool) {
	data, err := os.ReadFile(filepath.Join(btnStateDir, "hold", section))
	if err != nil {
		return btnHold{}, false
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return btnHold{}, false
	}
	until, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return btnHold{}, false
	}
	return btnHold{until: until, token: f[1]}, true
}

var (
	btnHoldMu   sync.Mutex
	btnHoldSeen = map[string]btnHoldMark{}
)

type btnHoldMark struct {
	token string
	off   bool
}

// btnScheduleHeld: a button turned this network on or off, so the Wi-Fi
// schedule leaves it alone: until the toggle's time is over, or, for a
// toggle without a time, until the schedule itself changes (its window
// starts or ends), when the schedule takes over again.
func btnScheduleHeld(section string, off bool) bool {
	h, ok := btnReadHold(section)
	if !ok {
		return false
	}
	path := filepath.Join(btnStateDir, "hold", section)
	if h.until > 0 {
		if btnNow().Unix() < h.until {
			return true
		}
		_ = os.Remove(path)
		return false
	}
	btnHoldMu.Lock()
	defer btnHoldMu.Unlock()
	m, ok := btnHoldSeen[section]
	if !ok || m.token != h.token {
		btnHoldSeen[section] = btnHoldMark{token: h.token, off: off}
		return true
	}
	if m.off == off {
		return true
	}
	delete(btnHoldSeen, section)
	_ = os.Remove(path)
	return false
}
