package modules

import (
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// A station becomes plain signal values; anything odd in it is dropped, and
// wired stations (which UniFi cannot place reliably) give nothing.
func TestQStationObs(t *testing.T) {
	for _, c := range []struct {
		in   probe.QuarantineStation
		want string
	}{
		{probe.QuarantineStation{Wired: true, Proto: "ax"}, ""},
		{probe.QuarantineStation{APModel: "U7-Pro", Band: "5g", Proto: "be", NSS: 2, MLO: true}, "U7-Pro/5g:be,mlo"},
		{probe.QuarantineStation{APModel: "U6\u202eLR!", Band: "2g", Proto: "AX", NSS: 1}, "U6LR/2g:ax"},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "9g", Proto: "ax"}, "U6-LR/:ax"},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g", Proto: "a x"}, ""},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g", Proto: "abcde"}, ""},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g"}, ""},
	} {
		got, ok := qStationObs(c.in)
		if got.radio != c.want || ok != (c.want != "") {
			t.Errorf("%+v: %+v %v, want %q", c.in, got, ok, c.want)
		}
	}
}

// The answer is used only while recent, and only well-formed MACs count.
func TestQuarantineNoteStations(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	old := qStationsNow
	qStationsNow = func() time.Time { return now }
	t.Cleanup(func() {
		qStationsNow = old
		qStationsMu.Lock()
		qStations = nil
		qStationsMu.Unlock()
	})
	QuarantineNoteStations([]probe.QuarantineStation{
		{MAC: "02:00:00:00:00:10", Wired: true},
		{MAC: "02:00:00:00:00:1G", Proto: "ax"},
		{MAC: " 02:00:00:00:00:11 ", APModel: "U7-Pro", Band: "5g", Proto: "be"},
	})
	u, ok := qStationsSnapshot(now.Add(time.Minute))
	if !ok || len(u) != 1 || u["02:00:00:00:00:11"].radio != "U7-Pro/5g:be" {
		t.Fatalf("snapshot: %v %v", u, ok)
	}
	if _, ok := qStationsSnapshot(now.Add(qStationsMaxAge + time.Second)); ok {
		t.Fatal("an old answer was used")
	}
}

// UniFi's view: a new Wi-Fi standard, or losing Wi-Fi 7 multi-link, on a
// known access point model and band is a notice; a new model or band is
// learned. It never makes more than a notice alone.
func TestDetectUnifiSignals(t *testing.T) {
	f := newQDetectFake(t, true)
	f.seeAsUsual()
	f.obs.unifi = map[string]qUnifiObs{qPhone: {radio: "U7-Pro/5g:be,mlo"}}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	f.obs.fp[qPhone] = qFP{opts: "1,3,6,15,119", vendor: "android-dhcp-14", at: f.now.Unix()}

	f.obs.unifi[qPhone] = qUnifiObs{radio: "U6-LR/5g:ax"}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("another access point model was reported: %+v", s)
	}
	if v := loadQState().Detect.Profiles[qPhone].Values[qSigURadio]; len(v) != 2 {
		t.Fatalf("the new model was not learned: %v", v)
	}

	f.now = f.now.Add(time.Minute)
	f.obs.unifi[qPhone] = qUnifiObs{radio: "U7-Pro/5g:ax"}
	f.check(t)
	s := loadQState().Detect.Suspects[qPhone]
	if s == nil || s.Level != "notice" || len(s.Signals) != 1 || s.Signals[0].Kind != qSigURadio || len(s.Signals[0].Was) != 1 || s.Signals[0].Was[0] != "U7-Pro/5g:be,mlo" {
		t.Fatalf("a Wi-Fi 6 device where a Wi-Fi 7 one was: %+v", s)
	}
}

// The report: approved and waiting devices, with the open reports.
func TestQuarantineReportInfo(t *testing.T) {
	f := newQDetectFake(t, false)
	if info := quarantineReportInfo(); info == nil || !info.Enabled || len(info.Devices) != 1 || info.Devices[0] != (probe.QuarantineDevice{MAC: qPhone, State: "approved"}) {
		t.Fatalf("approved only: %+v", info)
	}
	qMu.Lock()
	st := loadQState()
	st.Pending["02:00:00:00:00:20"] = QPending{FirstSeen: f.now.Unix(), LastSeen: f.now.Unix()}
	st.Detect.Suspects = map[string]*QSuspect{
		qPhone:              {Level: "alert", Signals: []QSignal{{Kind: qSigDHCP, Now: "1,2"}}},
		"02:00:00:00:00:20": {Level: "notice", Signals: []QSignal{{Kind: qSigHostname, Now: "x", Dismissed: true}}},
	}
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
	qMu.Unlock()
	info := quarantineReportInfo()
	want := []probe.QuarantineDevice{{MAC: qPhone, State: "approved", Report: "alert"}, {MAC: "02:00:00:00:00:20", State: "waiting"}}
	if info == nil || len(info.Devices) != 2 || info.Devices[0] != want[0] || info.Devices[1] != want[1] || info.PauseUntil != 0 {
		t.Fatalf("report: %+v", info)
	}

	// Moved back automatically and not back yet: listed as waiting, with
	// its alert; a running pause is reported.
	qMu.Lock()
	st = loadQState()
	st.Detect.Suspects["02:00:00:00:00:30"] = &QSuspect{Level: "alert", Action: "quarantined", Signals: []QSignal{{Kind: qSigDHCP, Now: "1,2"}}}
	st.Pause = QPause{Until: time.Now().Add(time.Hour).Unix(), Kind: "off"}
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
	qMu.Unlock()
	info = quarantineReportInfo()
	if info == nil || len(info.Devices) != 3 || info.Devices[2] != (probe.QuarantineDevice{MAC: "02:00:00:00:00:30", State: "waiting", Report: "alert"}) || info.PauseKind != "off" {
		t.Fatalf("report: %+v", info)
	}
}

// Roaming between two access points and a UniFi change are one event seen
// twice: an alert, but no automatic move.
func TestDetectUnifiNeverMovesAutomatically(t *testing.T) {
	f := newQDetectFake(t, true)
	tv := "02:00:00:00:00:20"
	if _, err := QuarantineApprove([]QApproveItem{{MAC: tv}}); err != nil {
		t.Fatal(err)
	}
	QuarantineNoteViewer("192.0.2.10")
	qViewersMu.Lock()
	qViewers[qPhone] = f.now
	qViewersMu.Unlock()
	f.seeAsUsual()
	f.obs.unifi = map[string]qUnifiObs{tv: {radio: "U7-Pro/5g:be,mlo"}}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	f.seeAsUsual()
	f.obs.unifi[tv] = qUnifiObs{radio: "U7-Pro/5g:ax"}
	at := f.now.Add(-90 * time.Second)
	f.obs.roam = map[string][]qRoamHit{tv: {{ap: "198.51.100.1", at: at}, {ap: "198.51.100.2", at: at.Add(20 * time.Second)}, {ap: "198.51.100.1", at: at.Add(40 * time.Second)}, {ap: "198.51.100.2", at: at.Add(60 * time.Second)}}}
	f.check(t)
	st := loadQState()
	s := st.Detect.Suspects[tv]
	if s == nil || s.Level != "alert" || len(s.Signals) != 2 {
		t.Fatalf("roam and a UniFi change: %+v", s)
	}
	if _, ok := st.Approved[tv]; !ok {
		t.Fatal("moved to quarantine on roaming and UniFi evidence")
	}
	if !strings.Contains(strings.Join(f.messages(), "\n"), "relayed from UniFi") {
		t.Fatalf("messages: %q", f.messages())
	}
}

// The report comes from the last save, not from parsing the state on each
// push; with nothing saved yet it is read once from the state on disk, and
// an ended pause is not reported.
func TestQuarantineReportSnapshot(t *testing.T) {
	newQDetectFake(t, false)
	// A report from another state file (an earlier start) is not used.
	qReportSnap.Store(&qReport{info: &probe.QuarantineInfo{Enabled: true}, path: "/elsewhere"})
	if info := quarantineReportInfo(); info == nil || len(info.Devices) != 1 {
		t.Fatalf("not read from this state: %+v", info)
	}
	if r := qReportSnap.Load(); r == nil || r.path != qStatePath {
		t.Fatal("the report read from disk was not kept")
	}

	// Once published, a push does not parse the state: changing only the
	// cached JSON (as no real save does) is not seen.
	qCacheMu.Lock()
	qCacheRaw = []byte(`{"enabled":false}`)
	qCacheMu.Unlock()
	if info := quarantineReportInfo(); info == nil || !info.Enabled {
		t.Fatalf("the state was parsed again: %+v", info)
	}

	// A save publishes the new state; an ended pause is dropped by the
	// reader without changing the published report.
	qMu.Lock()
	st := loadQState()
	st.Enabled = true
	st.Pause = QPause{Until: time.Now().Add(-time.Minute).Unix(), Kind: "off"}
	if err := saveQState(st); err != nil {
		t.Fatal(err)
	}
	qMu.Unlock()
	if info := quarantineReportInfo(); info == nil || info.PauseKind != "" || info.PauseUntil != 0 {
		t.Fatalf("an ended pause was reported: %+v", info)
	}
	if r := qReportSnap.Load(); r.info.PauseKind != "off" {
		t.Fatal("the published report was changed")
	}
}
