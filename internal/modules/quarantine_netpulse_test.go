package modules

import (
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// A station becomes plain signal values; anything odd in it is dropped.
func TestQStationObs(t *testing.T) {
	for _, c := range []struct {
		in           probe.QuarantineStation
		medium, want string
	}{
		{probe.QuarantineStation{Wired: true, Proto: "ax"}, "wired", ""},
		{probe.QuarantineStation{APModel: "U7-Pro", Band: "5g", Proto: "be", NSS: 2, MLO: true}, "wifi", "U7-Pro/5g/mlo:be,nss2"},
		{probe.QuarantineStation{APModel: "U6‮LR!", Band: "2g", Proto: "AX"}, "wifi", "U6LR/2g:ax"},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "9g", Proto: "ax", NSS: 99}, "wifi", "U6-LR/:ax"},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g", Proto: "a x"}, "wifi", ""},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g", Proto: "abcde"}, "wifi", ""},
		{probe.QuarantineStation{APModel: "U6-LR", Band: "5g"}, "wifi", ""},
	} {
		got := qStationObs(c.in)
		if got.medium != c.medium || got.radio != c.want {
			t.Errorf("%+v: %+v, want %s %q", c.in, got, c.medium, c.want)
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
		{MAC: "02:00:00:00:00:1G", Wired: true},
		{MAC: " 02:00:00:00:00:11 "},
	})
	u, ok := qStationsSnapshot(now.Add(time.Minute))
	if !ok || len(u) != 2 || u["02:00:00:00:00:10"].medium != "wired" || u["02:00:00:00:00:11"].medium != "wifi" {
		t.Fatalf("snapshot: %v %v", u, ok)
	}
	if _, ok := qStationsSnapshot(now.Add(qStationsMaxAge + time.Second)); ok {
		t.Fatal("an old answer was used")
	}
}

// UniFi's view: a new Wi-Fi standard on a known access point model and band
// is a notice; a new model or band is learned; a move to a cable together
// with a radio change is still one source (no alert, no automatic move).
func TestDetectUnifiSignals(t *testing.T) {
	f := newQDetectFake(t, true)
	QuarantineNoteViewer("192.0.2.99") // a panel device is known, so auto may act
	f.seeAsUsual()
	f.obs.unifi = map[string]qUnifiObs{qPhone: {medium: "wifi", radio: "U7-Pro/5g:ax,nss2"}}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	f.obs.fp[qPhone] = qFP{opts: "1,3,6,15,119", vendor: "android-dhcp-14", at: f.now.Unix()}

	f.obs.unifi[qPhone] = qUnifiObs{medium: "wifi", radio: "U6-LR/5g:ax,nss2"}
	f.check(t)
	if s := loadQState().Detect.Suspects[qPhone]; s != nil {
		t.Fatalf("another access point model was reported: %+v", s)
	}
	if v := loadQState().Detect.Profiles[qPhone].Values[qSigURadio]; len(v) != 2 {
		t.Fatalf("the new model was not learned: %v", v)
	}

	f.now = f.now.Add(time.Minute)
	f.obs.unifi[qPhone] = qUnifiObs{medium: "wifi", radio: "U7-Pro/5g:n,nss1"}
	f.check(t)
	s := loadQState().Detect.Suspects[qPhone]
	if s == nil || s.Level != "notice" || len(s.Signals) != 1 || s.Signals[0].Kind != qSigURadio || len(s.Signals[0].Was) != 1 || s.Signals[0].Was[0] != "U7-Pro/5g:ax,nss2" {
		t.Fatalf("a different radio on a known model and band: %+v", s)
	}

	f.now = f.now.Add(time.Minute)
	f.obs.unifi[qPhone] = qUnifiObs{medium: "wired"}
	f.check(t)
	st := loadQState()
	s = st.Detect.Suspects[qPhone]
	if s == nil || s.Level != "notice" || len(s.Signals) != 2 {
		t.Fatalf("UniFi alone made more than a notice: %+v", s)
	}
	if _, ok := st.Approved[qPhone]; !ok {
		t.Fatal("UniFi alone moved a device back to quarantine")
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
	if info == nil || len(info.Devices) != 2 || info.Devices[0] != want[0] || info.Devices[1] != want[1] {
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
	f.obs.unifi = map[string]qUnifiObs{tv: {medium: "wifi", radio: "U7-Pro/5g:ax,nss2"}}
	f.check(t)
	f.now = f.now.Add(qDetectLearn + time.Minute)
	f.seeAsUsual()
	f.obs.unifi[tv] = qUnifiObs{medium: "wifi", radio: "U7-Pro/5g:ac,nss1"}
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
