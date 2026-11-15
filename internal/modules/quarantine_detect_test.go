package modules

import (
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
)

// qDetectFake runs the detection on observations the test sets.
type qDetectFake struct {
	*qFake
	obs qObs
	now time.Time
}

func newQDetectFake(t *testing.T, auto bool) *qDetectFake {
	f := &qDetectFake{qFake: newQFake(t), now: time.Unix(1_800_000_000, 0)}
	f.enable(t, "internet", "home") // approves the requester, 02:00:00:00:00:10
	qChannelsFn = func() bool { return true }
	old := qObserveFn
	t.Cleanup(func() {
		qObserveFn = old
		qPlacesSeen, qMassRecent, qMassToldAt = map[string]time.Time{}, map[string]time.Time{}, time.Time{}
		qResetViewers()
	})
	qPlacesSeen, qMassRecent, qMassToldAt = map[string]time.Time{}, map[string]time.Time{}, time.Time{}
	qResetViewers()
	f.obs = qObs{fp: map[string]qFP{}, leases: map[string][]ubus.Lease{}, leasesOK: true, uptimeOK: true, neigh: map[string][]qNeigh{}, radio: map[string]string{}}
	qObserveFn = func(time.Time) qObs { return f.obs }
	if _, err := QuarantineDetectSet(true, auto); err != nil {
		t.Fatal(err)
	}
	return f
}

// check runs one full check at f.now.
func (f *qDetectFake) check(t *testing.T) {
	t.Helper()
	qMu.Lock()
	st := loadQState()
	moved, _ := qDetectLocked(st, f.now)
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
	if moved {
		if err := qChangeLocked(st); err != nil {
			t.Fatal(err)
		}
	}
	qMu.Unlock()
	time.Sleep(20 * time.Millisecond) // messages go out asynchronously
}

func (f *qDetectFake) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.notified...)
}

const qPhone = "02:00:00:00:00:10"

func (f *qDetectFake) seeAsUsual() {
	f.obs.fp[qPhone] = qFP{opts: "1,3,6,15,119", vendor: "android-dhcp-14", at: f.now.Unix()}
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "phone", ClientID: "client-id-1"}}
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.10", dev: "br-home"}}
}

func TestDetectLearnsFirstThenReports(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	// While learning, a second state is learned, not reported.
	f.now = f.now.Add(time.Hour)
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "phone-2", ClientID: "client-id-1"}}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("reported while learning: %+v", s)
	}
	// After learning, a known state (back and forth) is fine...
	f.now = f.now.Add(qDetectLearn)
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "phone", ClientID: "client-id-1"}}
	f.check(t)
	if len(f.messages()) != 0 {
		t.Fatalf("a known state was reported: %q", f.messages())
	}
	// ...a new hostname alone is a notice.
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "laptop", ClientID: "client-id-1"}}
	f.check(t)
	s := loadQState().Detect.Suspects[qPhone]
	if s == nil || s.Level != "notice" || len(s.Signals) != 1 || s.Signals[0].Kind != qSigHostname {
		t.Fatalf("hostname change: %+v", s)
	}
	if m := f.messages(); len(m) != 1 || !strings.Contains(m[0], "hostname: laptop") || !strings.Contains(m[0], "known: phone-2 | phone") && !strings.Contains(m[0], "known: phone | phone-2") {
		t.Fatalf("notice: %q", m)
	}
	// The same evidence again: no new message.
	f.now = f.now.Add(qNotifyGap + time.Minute)
	f.check(t)
	if len(f.messages()) != 1 {
		t.Fatalf("the same evidence was announced again: %d", len(f.messages()))
	}
	// A new DHCP fingerprint: strong, an alert. Alerts only: still approved.
	f.obs.fp[qPhone] = qFP{opts: "1,121,3,6,15,108,114,119,252", vendor: "", at: f.now.Unix()}
	f.check(t)
	st := loadQState()
	if s := st.Detect.Suspects[qPhone]; s.Level != "alert" {
		t.Fatalf("fingerprint change: %+v", s)
	}
	if _, ok := st.Approved[qPhone]; !ok {
		t.Fatal("moved to quarantine without the automatic action")
	}
	if m := f.messages(); len(m) != 2 || !strings.Contains(m[1], "Possible copied MAC") || !strings.Contains(m[1], "DHCP fingerprint: 1,121,3,6,15,108,114,119,252") {
		t.Fatalf("alert: %q", m)
	}
	// "Same device" learns the reported values: nothing is reported again.
	if _, err := QuarantineSuspectResolve(qPhone, "same"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	f.obs.fp[qPhone] = qFP{opts: "1,121,3,6,15,108,114,119,252", at: f.now.Unix()}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("accepted values reported again: %+v", s)
	}
}

func TestDetectTwoMediumSignalsMakeAnAlert(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	// An address it was not given, then a new client id within the hour.
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.77", dev: "br-home"}}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s == nil || s.Level != "notice" || s.Signals[0].Kind != qSigIP {
		t.Fatalf("unleased address: %+v", s)
	}
	f.now = f.now.Add(20 * time.Minute)
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "phone", ClientID: "ff:00:00:00:01"}}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s.Level != "alert" {
		t.Fatalf("two signals within the window: %+v", s)
	}
}

func TestDetectAutomaticMoveAndItsLimits(t *testing.T) {
	f := newQDetectFake(t, true)
	tv, tvPair := "02:00:00:00:00:20", "02:00:00:00:00:31"
	for _, m := range []string{tv, "02:00:00:00:00:30", tvPair} {
		if _, err := QuarantineApprove([]QApproveItem{{MAC: m}}); err != nil {
			t.Fatal(err)
		}
	}
	usual := func() {
		f.seeAsUsual()
		f.obs.fp[tv] = qFP{opts: "1,3,6", at: f.now.Unix()}
		f.obs.leases[tv] = []ubus.Lease{{MAC: tv, IP: "192.0.2.20", Hostname: "tv"}}
		f.obs.neigh[tv] = []qNeigh{{ip: "192.0.2.20", dev: "br-home"}}
	}
	usual()
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	copied := func(mac string) {
		f.obs.fp[mac] = qFP{opts: "1,121,3,6,15,119,252", at: f.now.Unix()}
		f.obs.leases[mac] = []ubus.Lease{{MAC: mac, IP: "192.0.2.21", Hostname: "android-1"}}
	}

	// No device used for the panel is known yet: nothing is moved.
	copied(tv)
	f.check(t)
	if _, ok := loadQState().Approved[tv]; !ok {
		t.Fatal("moved before any panel device was known")
	}
	if !strings.Contains(strings.Join(f.messages(), "\n"), "no device used for this panel is known yet") {
		t.Fatalf("messages: %q", f.messages())
	}
	_, _ = QuarantineSuspectResolve(tv, "same")

	// The panel's device is known (and kept across restarts, in the state).
	QuarantineNoteViewer("192.0.2.10")
	qViewersMu.Lock()
	if _, ok := qViewers[qPhone]; !ok {
		t.Fatal("the panel request was not noted")
	}
	qViewers[qPhone] = f.now // the test's clock
	qViewersMu.Unlock()
	f.now = f.now.Add(qNotifyGap + time.Minute)
	usual()
	f.check(t)
	if st := loadQState(); st.Detect.Viewers[qPhone] == 0 {
		t.Fatalf("the panel device was not remembered: %+v", st.Detect.Viewers)
	}
	// The user's own device (and its Wi-Fi 7 pair) is never moved.
	copied(qPhone)
	f.check(t)
	if _, ok := loadQState().Approved[qPhone]; !ok {
		t.Fatal("the device used for the panel was moved to quarantine")
	}
	// One strong signal alone (an OS update) alerts but does not move.
	f.now = f.now.Add(qNotifyGap + time.Minute)
	f.obs.fp[tv] = qFP{opts: "1,3,6,42", at: f.now.Unix()}
	f.check(t)
	st := loadQState()
	if s := st.Detect.Suspects[tv]; s == nil || s.Level != "alert" {
		t.Fatalf("fingerprint change: %+v", s)
	}
	if _, ok := st.Approved[tv]; !ok {
		t.Fatal("moved on one kind of evidence")
	}
	// Two kinds: moved, and its pair is not protected by it.
	f.now = f.now.Add(qNotifyGap + time.Minute)
	f.obs.leases[tv] = []ubus.Lease{{MAC: tv, IP: "192.0.2.20", Hostname: "android-2"}}
	f.check(t)
	st = loadQState()
	if _, ok := st.Approved[tv]; ok {
		t.Fatal("the automatic action did not move the device")
	}
	if s := st.Detect.Suspects[tv]; s == nil || s.Action != "quarantined" {
		t.Fatalf("report: %+v", s)
	}
	if !strings.Contains(strings.Join(f.messages(), "\n"), "It was moved back to quarantine") {
		t.Fatalf("messages: %q", f.messages())
	}
	// Approving it again closes the report.
	if _, err := QuarantineApprove([]QApproveItem{{MAC: tv}}); err != nil {
		t.Fatal(err)
	}
	f.check(t)
	if s := loadQState().Detect.Suspects[tv]; s != nil {
		t.Fatalf("a report outlived the new approval: %+v", s)
	}
	// A Wi-Fi 7 pair of the panel device is protected through it.
	if why := qProtected(func() *qState {
		st := loadQState()
		st.Pairs = map[string]QPair{tvPair: {Partner: qPhone}, qPhone: {Partner: tvPair}}
		return st
	}())(tvPair); !strings.Contains(why, "Wi-Fi 7 pair") {
		t.Fatalf("pair protection: %q", why)
	}
}

func TestDetectSeveralNetworksMustLast(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	// A phone that just moved to another VLAN is briefly on both.
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.10", dev: "br-home"}, {ip: "192.0.2.10", dev: "br-iot"}}
	f.check(t)
	f.now = f.now.Add(30 * time.Second)
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.10", dev: "br-iot"}}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("a move between networks was reported: %+v", s)
	}
	// On both for over a minute: reported.
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.10", dev: "br-home"}, {ip: "192.0.2.10", dev: "br-iot"}}
	f.check(t)
	f.now = f.now.Add(qPlacesHold + time.Second)
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s == nil || s.Signals[0].Kind != qSigPlaces {
		t.Fatalf("lasting: %+v", s)
	}
}

func TestDetectDismissStaysQuietUntilNewEvidence(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	f.obs.neigh[qPhone] = []qNeigh{{ip: "192.0.2.77", dev: "br-home"}}
	f.check(t)
	if _, err := QuarantineSuspectResolve(qPhone, "dismiss"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(qNotifyGap + time.Minute)
		f.check(t)
	}
	if n := len(f.messages()); n != 1 {
		t.Fatalf("dismissed evidence was announced again: %d messages", n)
	}
	for _, r := range ProbeQuarantine().Detect.Suspects {
		if r.MAC == qPhone {
			t.Fatal("a dismissed report is still listed")
		}
	}
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "other"}}
	f.check(t)
	if n := len(f.messages()); n != 2 {
		t.Fatalf("new evidence did not reopen it: %d messages", n)
	}
}

func TestDetectNoLeaseRightAfterAReboot(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	// /tmp's leases are gone after a reboot; the device still uses its address.
	delete(f.obs.leases, qPhone)
	f.obs.uptimeOK = false
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("reported after a reboot: %+v", s)
	}
	// Leases on two networks: either address is its own.
	f.obs.uptimeOK = true
	f.obs.leases[qPhone] = []ubus.Lease{{MAC: qPhone, IP: "192.0.2.10", Hostname: "phone"}, {MAC: qPhone, IP: "198.51.100.10", Hostname: "phone"}}
	f.obs.neigh[qPhone] = []qNeigh{{ip: "198.51.100.10", dev: "br-guest"}}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("its second lease was reported: %+v", s)
	}
}

func TestDetectManyAtOnceIsTheRouterNotACopy(t *testing.T) {
	f := newQDetectFake(t, true)
	var macs []string
	for i := 0; i < qMassChange; i++ {
		m := "02:00:00:00:01:" + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
		macs = append(macs, m)
		if _, err := QuarantineApprove([]QApproveItem{{MAC: m}}); err != nil {
			t.Fatal(err)
		}
		f.obs.fp[m] = qFP{opts: "1,3,6", at: f.now.Unix()}
	}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	// They reconnect over a few minutes, a few per check.
	for i, m := range macs {
		f.obs.fp[m] = qFP{opts: "1,3,6,42", at: f.now.Unix()}
		f.obs.leases[m] = []ubus.Lease{{MAC: m, IP: "192.0.2.200", Hostname: "renamed"}}
		if i%3 == 2 {
			f.now = f.now.Add(time.Minute)
			f.check(t)
		}
	}
	f.check(t)
	st := loadQState()
	for _, m := range macs {
		if _, ok := st.Approved[m]; !ok {
			t.Fatalf("%s moved during a change on the router side", m)
		}
	}
	var summaries int
	for _, m := range f.messages() {
		if strings.Contains(m, "changed within minutes") {
			summaries++
		}
	}
	if summaries != 1 {
		t.Fatalf("expected one summary: %q", f.messages())
	}
}

func TestDetectOffForgetsProfiles(t *testing.T) {
	f := newQDetectFake(t, false)
	f.seeAsUsual()
	f.check(t)
	if len(loadQState().Detect.Profiles) == 0 {
		t.Fatal("no profile was started")
	}
	if _, err := QuarantineDetectSet(false, false); err != nil {
		t.Fatal(err)
	}
	if d := loadQState().Detect; d.Enabled || len(d.Profiles) != 0 {
		t.Fatalf("turned off but kept: %+v", d)
	}
}

func TestQRoamFlipping(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	hits := func(aps ...string) []qRoamHit {
		var h []qRoamHit
		for i, a := range aps {
			h = append(h, qRoamHit{ap: a, at: at.Add(time.Duration(i) * time.Second)})
		}
		return h
	}
	if v := qRoamFlipping(hits("192.0.2.2", "192.0.2.3", "192.0.2.2", "192.0.2.3")); v != "192.0.2.2 ↔ 192.0.2.3" {
		t.Fatalf("A B A B: %q", v)
	}
	if v := qRoamFlipping(hits("192.0.2.2", "192.0.2.3", "192.0.2.2")); v != "" {
		t.Fatalf("one roam and back is normal: %q", v)
	}
	if v := qRoamFlipping(hits("192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.2")); v != "" {
		t.Fatalf("a walk through three access points is roaming: %q", v)
	}
	if v := qRoamFlipping(hits("192.0.2.2", "192.0.2.2", "192.0.2.3", "192.0.2.3")); v != "" {
		t.Fatalf("repeats are one stay: %q", v)
	}
}

func TestQParseDetectSources(t *testing.T) {
	fp := qParseFingerprints("02:00:00:00:00:0A\t1,3,6\tandroid\t1800000000\nbroken\n02:00:00:00:00:0b\t\t\t1\n")
	if len(fp) != 1 || fp["02:00:00:00:00:0a"].opts != "1,3,6" || fp["02:00:00:00:00:0a"].at != 1800000000 {
		t.Fatalf("fingerprints: %+v", fp)
	}
	n := qParseNeighbours("192.0.2.5 dev br-home lladdr 02:00:00:00:00:0A REACHABLE\n192.0.2.6 dev br-home  FAILED\n192.0.2.7 dev br-iot lladdr 02:00:00:00:00:0b router STALE\n")
	if len(n) != 2 || n[0].mac != "02:00:00:00:00:0a" || n[0].state != "REACHABLE" || n[1].dev != "br-iot" || n[1].state != "STALE" {
		t.Fatalf("neighbours: %+v", n)
	}
	sig := qRadioSignature(5180, map[string]any{"ht": true, "vht": true, "he": false, "mfp": true})
	if sig != "5g:ht,mfp,vht" {
		t.Fatalf("radio: %q", sig)
	}
	// Capabilities are compared within a band: a first 2.4 GHz connection
	// is learned, not reported.
	p := &QProfile{Values: map[string][]string{qSigRadio: {"5g:ht,mfp,vht"}}}
	if !qKnown(p, qSigRadio, "2g:ht,mfp") || qKnown(p, qSigRadio, "5g:ht") {
		t.Fatal("per-band comparison")
	}
}

func TestDetectAnUpdateOrADismissedAlertIsNotEnoughToMove(t *testing.T) {
	f := newQDetectFake(t, true)
	tv := "02:00:00:00:00:20"
	if _, err := QuarantineApprove([]QApproveItem{{MAC: tv}}); err != nil {
		t.Fatal(err)
	}
	qViewersMu.Lock()
	qViewers[qPhone] = f.now
	qViewersMu.Unlock()
	f.seeAsUsual()
	f.obs.fp[tv] = qFP{opts: "1,3,6", vendor: "android-dhcp-14", at: f.now.Unix()}
	f.obs.leases[tv] = []ubus.Lease{{MAC: tv, IP: "192.0.2.20", Hostname: "tv"}}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	// An OS update: a new option list and vendor class, one DHCP request.
	f.obs.fp[tv] = qFP{opts: "1,3,6,42", vendor: "android-dhcp-15", at: f.now.Unix()}
	f.check(t)
	st := loadQState()
	if s := st.Detect.Suspects[tv]; s == nil || s.Level != "alert" || len(s.Signals) != 2 {
		t.Fatalf("update: %+v", s)
	}
	if _, ok := st.Approved[tv]; !ok {
		t.Fatal("an OS update (one DHCP request) moved the device")
	}
	// Dismissed, then a harmless rename: a notice, not a move.
	if _, err := QuarantineSuspectResolve(tv, "dismiss"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(qNotifyGap + time.Minute)
	f.obs.leases[tv] = []ubus.Lease{{MAC: tv, IP: "192.0.2.20", Hostname: "tv-living"}}
	f.check(t)
	st = loadQState()
	if _, ok := st.Approved[tv]; !ok {
		t.Fatal("a dismissed alert plus a rename moved the device")
	}
	if s := st.Detect.Suspects[tv]; s == nil || s.Level != "notice" || s.Dismissed != 0 {
		t.Fatalf("reopened report: %+v", s)
	}
	for _, r := range ProbeQuarantine().Detect.Suspects {
		if r.MAC == tv && (len(r.Signals) != 1 || r.Signals[0].Kind != qSigHostname) {
			t.Fatalf("the panel shows dismissed evidence again: %+v", r.Signals)
		}
	}
}

// qResetViewers forgets the panel's devices and the per-IP throttle, so no
// test depends on which ran before it.
func qResetViewers() {
	qViewersMu.Lock()
	qViewers, qViewerIPAt = map[string]time.Time{}, map[string]time.Time{}
	qViewersMu.Unlock()
}
