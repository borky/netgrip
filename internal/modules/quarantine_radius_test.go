package modules

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const qTestRadiusSecret = "dummy-radius-secret"

// qRadiusRequest builds an Access-Request the way a UniFi access point does
// (MAC authentication), signed with secret unless sign is false.
func qRadiusRequest(t *testing.T, id byte, mac, called, secret string, sign bool) []byte {
	t.Helper()
	attrs := [][]byte{
		append([]byte{radAttrUserName, byte(2 + len(mac))}, mac...),
		append([]byte{radAttrCallingStation, byte(2 + len(mac))}, mac...),
		append([]byte{radAttrCalledStation, byte(2 + len(called))}, called...),
	}
	if sign {
		attrs = append(attrs, append([]byte{radAttrMessageAuth, 18}, make([]byte, 16)...))
	}
	body := bytes.Join(attrs, nil)
	b := make([]byte, radiusHeaderLen+len(body))
	b[0], b[1] = radiusAccessRequest, id
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	for i := 4; i < 20; i++ {
		b[i] = byte(i * 7) // a fixed dummy request authenticator
	}
	copy(b[radiusHeaderLen:], body)
	if sign {
		m := hmac.New(md5.New, []byte(secret))
		m.Write(b)
		copy(b[len(b)-16:], m.Sum(nil))
	}
	return b
}

// qCheckResponse verifies an answer the way the access point would.
func qCheckResponse(t *testing.T, resp, req []byte, secret string) byte {
	t.Helper()
	if len(resp) < radiusHeaderLen || resp[1] != req[1] {
		t.Fatalf("bad answer: %x", resp)
	}
	// Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
	check := append([]byte(nil), resp...)
	copy(check[4:20], req[4:20])
	sum := md5.Sum(append(append([]byte(nil), check...), secret...))
	if !bytes.Equal(sum[:], resp[4:20]) {
		t.Fatal("bad Response Authenticator")
	}
	// Message-Authenticator first, over the answer with the request
	// authenticator and the attribute zeroed (RFC 3579 3.2).
	if resp[20] != radAttrMessageAuth || resp[21] != 18 {
		t.Fatal("Message-Authenticator is not the first attribute")
	}
	zeroed := append([]byte(nil), check...)
	for i := 22; i < 38; i++ {
		zeroed[i] = 0
	}
	m := hmac.New(md5.New, []byte(secret))
	m.Write(zeroed)
	if !bytes.Equal(m.Sum(nil), resp[22:38]) {
		t.Fatal("bad Message-Authenticator in the answer")
	}
	return resp[0]
}

func qRadiusTestView(enabled bool, approved ...string) *qRadiusView {
	v := &qRadiusView{listen: true, enabled: enabled, approved: map[string]bool{}, secret: []byte(qTestRadiusSecret)}
	for _, m := range approved {
		v.approved[m] = true
	}
	return v
}

func qRadiusReset(t *testing.T) {
	t.Helper()
	old := qRadiusSnap.Load()
	t.Cleanup(func() { qRadiusSnap.Store(old) })
	qRadiusMu.Lock()
	qRadiusDupes, qRadiusAccepted = map[string]qRadiusDupe{}, map[string]time.Time{}
	qRadiusStats, qRadiusClients, qRadiusSSIDs = QRadiusStats{}, map[string]bool{}, map[string]bool{}
	qRadiusMu.Unlock()
	for len(qRadiusEvents) > 0 {
		<-qRadiusEvents
	}
}

func TestRadiusAcceptsApprovedRefusesOthers(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(qRadiusTestView(true, "02:00:00:00:00:0a"))
	now := time.Now()
	req := qRadiusRequest(t, 1, "02-00-00-00-00-0A", "02-00-00-00-00-F0:Home", qTestRadiusSecret, true)
	if code := qCheckResponse(t, qRadiusHandle(req, "192.0.2.20:40000", now), req, qTestRadiusSecret); code != radiusAccessAccept {
		t.Fatalf("approved device: code %d", code)
	}
	req = qRadiusRequest(t, 2, "02-00-00-00-00-0B", "02-00-00-00-00-F0:Home", qTestRadiusSecret, true)
	if code := qCheckResponse(t, qRadiusHandle(req, "192.0.2.20:40000", now), req, qTestRadiusSecret); code != radiusAccessReject {
		t.Fatalf("unknown device: code %d", code)
	}
	select {
	case e := <-qRadiusEvents:
		if e.mac != "02:00:00:00:00:0b" || e.ssid != "Home" || e.accepted {
			t.Fatalf("event: %+v", e)
		}
	default:
		t.Fatal("the refused device was not queued for the waiting list")
	}
	s := QuarantineRadiusStats()
	if s.Accepted != 1 || s.Rejected != 1 || strings.Join(s.Clients, ",") != "192.0.2.20" || strings.Join(s.SSIDs, ",") != "Home" {
		t.Fatalf("stats: %+v", s)
	}
}

func TestRadiusDropsUnauthenticatedRequests(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(qRadiusTestView(true, "02:00:00:00:00:0a"))
	now := time.Now()
	for name, req := range map[string][]byte{
		"no Message-Authenticator":   qRadiusRequest(t, 1, "02:00:00:00:00:0a", "x:Home", qTestRadiusSecret, false),
		"wrong secret":               qRadiusRequest(t, 2, "02:00:00:00:00:0a", "x:Home", "another-secret", true),
		"two Message-Authenticators": append(qRadiusRequest(t, 3, "02:00:00:00:00:0a", "x:Home", qTestRadiusSecret, true), append([]byte{radAttrMessageAuth, 18}, make([]byte, 16)...)...),
	} {
		if name == "two Message-Authenticators" {
			binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
		}
		if resp := qRadiusHandle(req, "192.0.2.20:40000", now); resp != nil {
			t.Errorf("%s: answered", name)
		}
	}
	if s := QuarantineRadiusStats(); s.BadAuth != 3 || s.Accepted != 0 {
		t.Fatalf("stats: %+v", s)
	}
}

func TestRadiusResendsTheSameAnswerToARetransmission(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(qRadiusTestView(true, "02:00:00:00:00:0a"))
	now := time.Now()
	req := qRadiusRequest(t, 9, "02:00:00:00:00:0a", "x:Home", qTestRadiusSecret, true)
	first := qRadiusHandle(req, "192.0.2.20:40000", now)
	// Meanwhile the device is revoked; the retransmission gets the answer
	// already given, not a new one.
	qRadiusSnap.Store(qRadiusTestView(true))
	if again := qRadiusHandle(req, "192.0.2.20:40000", now.Add(time.Second)); !bytes.Equal(first, again) {
		t.Fatal("a retransmission got a different answer")
	}
	if s := QuarantineRadiusStats(); s.Accepted != 1 {
		t.Fatalf("a retransmission was counted again: %+v", s)
	}
}

func TestRadiusDecide(t *testing.T) {
	now := time.Now()
	v := qRadiusTestView(false)
	if d := qRadiusDecide(v, "02:00:00:00:00:0b", now); !d.accept {
		t.Fatal("refused while the quarantine is off: access points still asking would lock everyone out")
	}
	v = qRadiusTestView(true)
	v.pause = QPause{Until: now.Add(time.Minute).Unix(), Kind: "learn"}
	if d := qRadiusDecide(v, "02:00:00:00:00:0b", now); !d.accept || !d.learn {
		t.Fatalf("learning pause: %+v", d)
	}
	v.pause.Kind = "off"
	if d := qRadiusDecide(v, "02:00:00:00:00:0b", now); !d.accept || d.learn || !d.record {
		t.Fatalf("protection paused: %+v", d)
	}
	v.pause = QPause{}
	if d := qRadiusDecide(v, "02:00:00:00:00:0b", now); d.accept {
		t.Fatalf("unknown device accepted: %+v", d)
	}
}

func TestRadiusMAC(t *testing.T) {
	for in, want := range map[string]string{
		"02-00-00-00-00-AB": "02:00:00:00:00:ab",
		"0200000 000ab":     "02:00:00:00:00:ab",
		"02:00:00:00:00:ab": "02:00:00:00:00:ab",
		"0200.0000.00AB":    "02:00:00:00:00:ab",
		"not a mac":         "",
		"02:00:00:00:00":    "",
	} {
		if got := radiusMAC(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if radiusSSID("02-00-00-00-00-F0:Home:Net") != "Home:Net" || radiusSSID("Home") != "" {
		t.Fatal("SSID from Called-Station-Id")
	}
}

func TestQMLOPartner(t *testing.T) {
	approved := map[string]bool{"02:00:00:00:00:41": true}
	if qMLOPartner("02:00:00:00:00:42", approved) != "02:00:00:00:00:41" || qMLOPartner("02:00:00:00:00:40", approved) != "02:00:00:00:00:41" {
		t.Fatal("one apart in the last octet")
	}
	if qMLOPartner("02:00:00:00:00:43", approved) != "" || qMLOPartner("02:00:00:00:01:42", approved) != "" {
		t.Fatal("not a partner")
	}
	approved["02:00:00:00:00:43"] = true
	if qMLOPartner("02:00:00:00:00:42", approved) != "" {
		t.Fatal("two candidates must not be guessed")
	}
}

func TestQuarantineRadiusEndToEnd(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qRadiusReset(t)
	oKey := secretKeyPath
	secretKeyPath = filepath.Join(t.TempDir(), "secrets.key")
	t.Cleanup(func() { secretKeyPath = oKey })

	w := newQWifiFake(t, f)
	// Two zones: one rule each (fw4 takes one zone per rule).
	if _, err := QuarantineRadiusEnable([]string{"home", "guests"}); err != nil {
		t.Fatal(err)
	}
	r0, r1 := w.v.firewall[qRadiusRulePfx+"0"], w.v.firewall[qRadiusRulePfx+"1"]
	if r0.Option("src") != "guests" || r1.Option("src") != "home" || r0.Option("dest_port") != "1812" || !strings.HasPrefix(r1.Option("name"), "netgrip quarantine: ") {
		t.Fatalf("firewall rules: %+v %+v", r0.Options, r1.Options)
	}
	// Back to one zone: the other rule goes.
	if _, err := QuarantineRadiusEnable([]string{"home"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.v.firewall[qRadiusRulePfx+"1"]; ok || w.v.firewall[qRadiusRulePfx+"0"].Option("src") != "home" {
		t.Fatalf("rules after narrowing: %+v", w.v.firewall)
	}
	secret, err := QuarantineRadiusSecret()
	if err != nil || len(secret) != 24 {
		t.Fatalf("secret: %q %v", secret, err)
	}
	if st := loadQState(); !st.Radius.Enabled || strings.Contains(st.Radius.Secret, secret) {
		t.Fatalf("the secret must be stored sealed: %+v", st.Radius)
	}
	// The answer comes from the snapshot the save published.
	req := qRadiusRequest(t, 1, "02-00-00-00-00-10", "x:Home", secret, true) // the approved requester
	if code := qCheckResponse(t, qRadiusHandle(req, "192.0.2.20:1", time.Now()), req, secret); code != radiusAccessAccept {
		t.Fatalf("approved device refused: %d", code)
	}
	// A refused Wi-Fi 7 address one apart from an approved device waits,
	// with the hint, even right after that device was let in: a join
	// attempt is never approved by pairing.
	qRadiusRecord(qRadiusEvent{mac: "02:00:00:00:00:11", at: time.Now()})
	if _, ok := loadQState().Approved["02:00:00:00:00:11"]; ok {
		t.Fatal("a refused join one apart from an accepted device was approved")
	}
	if p := loadQState().Pending["02:00:00:00:00:11"]; p.PairOf != "02:00:00:00:00:10" {
		t.Fatalf("pending: %+v", p)
	}
	// The other way: RADIUS let in an approved address, and its data
	// address (never seen before) shows up on the network seconds later.
	st := loadQState()
	st.Approved["02:00:00:00:00:20"] = QApproved{At: 1, Name: "phone"}
	_ = saveQState(st)
	qRadiusMu.Lock()
	qRadiusAccepted["02:00:00:00:00:20"] = time.Now()
	qRadiusMu.Unlock()
	f.seen = []qElem{{Val: "02:00:00:00:00:21"}}
	qPoll(time.Now())
	if a, ok := loadQState().Approved["02:00:00:00:00:21"]; !ok || a.Via != "mlo" || a.Name != "phone" {
		t.Fatalf("data address not paired: %+v", loadQState().Approved)
	}
	// Once per accept: the other neighbour is not paired as well.
	f.seen = []qElem{{Val: "02:00:00:00:00:1f"}}
	qPoll(time.Now().Add(time.Second))
	if _, ok := loadQState().Approved["02:00:00:00:00:1f"]; ok {
		t.Fatal("a second address was paired with the same accept")
	}
	// Turning the quarantine off: RADIUS keeps answering, and accepts.
	if _, err := QuarantineDisable(); err != nil {
		t.Fatal(err)
	}
	req = qRadiusRequest(t, 2, "02-00-00-00-00-99", "x:Home", secret, true)
	if code := qCheckResponse(t, qRadiusHandle(req, "192.0.2.20:1", time.Now()), req, secret); code != radiusAccessAccept {
		t.Fatal("refused with the quarantine off")
	}
}

func FuzzParseRadius(f *testing.F) {
	f.Add([]byte{1, 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{1, 1, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2})
	f.Add([]byte{1, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0, 1, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parseRadius(b)
		if err != nil {
			return
		}
		total := radiusHeaderLen
		for _, a := range p.attrs {
			total += 2 + len(a.value)
		}
		if total != len(p.raw) {
			t.Fatalf("attributes cover %d of %d octets", total, len(p.raw))
		}
		_ = verifyRequestAuth(p, []byte("x"))
	})
}

func TestQuarantineRadiusBackupInfo(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(&qRadiusView{listen: false})
	if quarantineRadiusBackupInfo() != nil {
		t.Fatal("sent something although RADIUS was never set up")
	}
	qRadiusSnap.Store(&qRadiusView{listen: false, secret: []byte(qTestRadiusSecret)})
	if info := quarantineRadiusBackupInfo(); info == nil || !info.Disabled || info.Secret != "" {
		t.Fatalf("turned off: %+v (want a disabled marker without the secret)", info)
	}
	v := qRadiusTestView(true, "02:00:00:00:00:0b", "02:00:00:00:00:0a")
	v.pause = QPause{Until: time.Now().Add(time.Minute).Unix(), Kind: "learn"}
	qRadiusSnap.Store(v)
	info := quarantineRadiusBackupInfo()
	if info == nil || info.Secret != qTestRadiusSecret || !info.Enforce || strings.Join(info.Approved, ",") != "02:00:00:00:00:0a,02:00:00:00:00:0b" || info.PauseKind != "learn" {
		t.Fatalf("info: %+v", info)
	}
}

func TestRadiusLearningPauseKeepsWaitingDevicesOut(t *testing.T) {
	now := time.Now()
	v := qRadiusTestView(true)
	v.pause = QPause{Until: now.Add(time.Minute).Unix(), Kind: "learn"}
	v.waiting = map[string]bool{"02:00:00:00:00:0c": true}
	if d := qRadiusDecide(v, "02:00:00:00:00:0c", now); d.accept {
		t.Fatal("a device waiting before the pause was let in")
	}
	v.learned = qMaxLearned
	if d := qRadiusDecide(v, "02:00:00:00:00:0d", now); d.accept {
		t.Fatal("let in past the pause's maximum")
	}
}

func TestRadiusRefusesCredentialLogins(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(qRadiusTestView(true, "02:00:00:00:00:0a"))
	for _, typ := range []byte{radAttrEAPMessage, radAttrCHAPPassword} {
		req := qRadiusRequest(t, typ, "02-00-00-00-00-0A", "x:Home", qTestRadiusSecret, false)
		req = append(req, typ, 3, 1, radAttrMessageAuth, 18)
		req = append(req, make([]byte, 16)...)
		binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
		m := hmac.New(md5.New, []byte(qTestRadiusSecret))
		m.Write(req)
		copy(req[len(req)-16:], m.Sum(nil))
		if code := qCheckResponse(t, qRadiusHandle(req, "192.0.2.20:1", time.Now()), req, qTestRadiusSecret); code != radiusAccessReject {
			t.Fatalf("attribute %d: an approved MAC with a credential was accepted", typ)
		}
	}
}

func TestRadiusEchoesProxyState(t *testing.T) {
	qRadiusReset(t)
	qRadiusSnap.Store(qRadiusTestView(true, "02:00:00:00:00:0a"))
	req := qRadiusRequest(t, 5, "02-00-00-00-00-0A", "x:Home", qTestRadiusSecret, false)
	req = append(req, radAttrProxyState, 5, 'a', 'b', 'c', radAttrMessageAuth, 18)
	req = append(req, make([]byte, 16)...)
	binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
	m := hmac.New(md5.New, []byte(qTestRadiusSecret))
	m.Write(req)
	copy(req[len(req)-16:], m.Sum(nil))
	resp := qRadiusHandle(req, "192.0.2.20:1", time.Now())
	qCheckResponse(t, resp, req, qTestRadiusSecret)
	if !bytes.Contains(resp, []byte{radAttrProxyState, 5, 'a', 'b', 'c'}) {
		t.Fatal("Proxy-State not echoed")
	}
}

func TestRadiusSSIDColonFormat(t *testing.T) {
	if got := radiusSSID("02:00:00:00:00:f0:Home"); got != "Home" {
		t.Fatalf("colon MAC format: %q", got)
	}
}

func TestQMLONeverForAnnouncedOrChained(t *testing.T) {
	f := newQFake(t)
	f.enable(t, "internet", "home")
	qRadiusReset(t)
	st := loadQState()
	st.Approved["02:00:00:00:00:30"] = QApproved{At: 1}
	st.Approved["02:00:00:00:00:40"] = QApproved{At: 1, Via: "mlo"}
	st.Notified["02:00:00:00:00:31"] = 1 // already announced
	_ = saveQState(st)
	now := time.Now()
	qRadiusMu.Lock()
	qRadiusAccepted["02:00:00:00:00:30"] = now
	qRadiusAccepted["02:00:00:00:00:40"] = now
	qRadiusMu.Unlock()
	f.seen = []qElem{{Val: "02:00:00:00:00:31"}, {Val: "02:00:00:00:00:41"}}
	qPoll(now)
	got := loadQState().Approved
	if _, ok := got["02:00:00:00:00:31"]; ok {
		t.Fatal("an announced device was paired")
	}
	if _, ok := got["02:00:00:00:00:41"]; ok {
		t.Fatal("paired from an address that was itself paired")
	}
	// And the window is seconds, not a minute.
	qRadiusMu.Lock()
	qRadiusAccepted["02:00:00:00:00:30"] = now.Add(-qMLOWindow - time.Second)
	qRadiusMu.Unlock()
	f.seen = []qElem{{Val: "02:00:00:00:00:2f"}}
	qPoll(now.Add(time.Second))
	if _, ok := loadQState().Approved["02:00:00:00:00:2f"]; ok {
		t.Fatal("paired outside the window")
	}
}
