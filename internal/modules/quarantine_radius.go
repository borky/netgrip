package modules

// Device quarantine, UniFi layer (phase 3): a small RADIUS server for MAC
// authentication.
//
// An access point configured for "RADIUS MAC Authentication" asks, for every
// device that joins, whether to let it in. NetGrip answers from the approved
// list: Access-Accept (the device lands on the SSID's own network, as the
// access point is set up) or Access-Reject (the device cannot join; it shows
// up as waiting for approval and is announced like any other).
//
// Safety:
//   - every request must carry a valid Message-Authenticator (RFC 3579), and
//     every answer carries one first (the BlastRADIUS mitigation); the
//     shared secret is the only credential, sealed on disk;
//   - answers never wait for the quarantine's lock (which a radio restart
//     can hold for seconds): they come from an in-memory snapshot of the
//     approved list and the pause, refreshed whenever the state is saved;
//     recording a refusal or a learned approval is queued;
//   - nothing about a particular router or access point is assumed: the
//     access points are whoever sends requests signed with the secret, and
//     the firewall rule admits the zones the user picked.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netpulse/agent/probe"
)

const (
	radiusAccessRequest = 1
	radiusAccessAccept  = 2
	radiusAccessReject  = 3

	radAttrUserName       = 1
	radAttrReplyMessage   = 18
	radAttrCalledStation  = 30
	radAttrCallingStation = 31
	radAttrNASIdentifier  = 32
	radAttrMessageAuth    = 80
	radAttrNASIPAddress   = 4

	radiusHeaderLen = 20
	radiusMaxLen    = 4096
	qRadiusPort     = 1812

	qRadiusSecretField = "quarantine_radius_secret"
	qRadiusRule        = "netgrip_quarantine_radius"
)

// QRadiusState is the RADIUS layer's intent.
type QRadiusState struct {
	Enabled bool `json:"enabled"`
	// Secret is sealed (sealSecret); shown to the user once per request.
	Secret string `json:"secret,omitempty"`
	// Zones the access points live in: the firewall admits RADIUS from them.
	Zones []string `json:"zones,omitempty"`
}

// ---- Packets ----

type radiusPacket struct {
	code  byte
	id    byte
	auth  [16]byte
	attrs []radiusAttr
	raw   []byte
}

type radiusAttr struct {
	typ   byte
	value []byte
}

// parseRadius decodes a RADIUS packet. It refuses anything malformed: a
// length field that disagrees with the datagram, attributes that run past
// it, sizes outside RFC 2865's bounds. Pure, fuzzed.
func parseRadius(b []byte) (*radiusPacket, error) {
	if len(b) < radiusHeaderLen || len(b) > radiusMaxLen {
		return nil, errors.New("bad size")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < radiusHeaderLen || n > len(b) {
		return nil, errors.New("bad length field")
	}
	b = b[:n] // octets past Length are padding (RFC 2865 3)
	p := &radiusPacket{code: b[0], id: b[1], raw: append([]byte(nil), b...)}
	copy(p.auth[:], b[4:20])
	for i := radiusHeaderLen; i < n; {
		if i+2 > n {
			return nil, errors.New("truncated attribute")
		}
		l := int(b[i+1])
		if l < 2 || i+l > n {
			return nil, errors.New("bad attribute length")
		}
		p.attrs = append(p.attrs, radiusAttr{typ: b[i], value: append([]byte(nil), b[i+2:i+l]...)})
		i += l
	}
	return p, nil
}

func (p *radiusPacket) attr(t byte) ([]byte, int) {
	var v []byte
	count := 0
	for _, a := range p.attrs {
		if a.typ == t {
			if count == 0 {
				v = a.value
			}
			count++
		}
	}
	return v, count
}

// verifyRequestAuth checks a request's Message-Authenticator: exactly one,
// 16 octets, HMAC-MD5 over the packet with its value zeroed (RFC 3579 3.2).
func verifyRequestAuth(p *radiusPacket, secret []byte) bool {
	v, count := p.attr(radAttrMessageAuth)
	if count != 1 || len(v) != 16 {
		return false
	}
	buf := append([]byte(nil), p.raw...)
	for i := radiusHeaderLen; i < len(buf); {
		l := int(buf[i+1])
		if buf[i] == radAttrMessageAuth {
			for j := i + 2; j < i+l; j++ {
				buf[j] = 0
			}
		}
		i += l
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(buf)
	return hmac.Equal(mac.Sum(nil), v)
}

// buildRadiusResponse builds an Accept or Reject for a request: the
// Message-Authenticator first (BlastRADIUS), then the other attributes,
// then the Response Authenticator (RFC 2865 3).
func buildRadiusResponse(code byte, req *radiusPacket, secret []byte, extra []radiusAttr) []byte {
	attrs := append([]radiusAttr{{typ: radAttrMessageAuth, value: make([]byte, 16)}}, extra...)
	length := radiusHeaderLen
	for _, a := range attrs {
		length += 2 + len(a.value)
	}
	b := make([]byte, length)
	b[0], b[1] = code, req.id
	binary.BigEndian.PutUint16(b[2:4], uint16(length))
	copy(b[4:20], req.auth[:]) // the request authenticator, for both hashes
	i := radiusHeaderLen
	for _, a := range attrs {
		b[i], b[i+1] = a.typ, byte(2+len(a.value))
		copy(b[i+2:], a.value)
		i += 2 + len(a.value)
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(b)
	copy(b[radiusHeaderLen+2:radiusHeaderLen+18], mac.Sum(nil))
	sum := md5.Sum(append(append([]byte(nil), b...), secret...))
	copy(b[4:20], sum[:])
	return b
}

// radiusMAC normalises a MAC from Calling-Station-Id or User-Name
// ("02-00-00-00-00-AB", "0200000 000ab", "f6:34:...") to aa:bb:cc:dd:ee:ff.
func radiusMAC(v string) string {
	hexs := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + 'a' - 'A'
		}
		return -1
	}, v)
	if len(hexs) != 12 {
		return ""
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = hexs[2*i : 2*i+2]
	}
	return strings.Join(parts, ":")
}

// radiusSSID takes the SSID from Called-Station-Id ("<AP MAC>:<SSID>").
func radiusSSID(called string) string {
	if i := strings.Index(called, ":"); i >= 0 && radiusMAC(called[:i]) != "" {
		return called[i+1:]
	}
	return ""
}

// ---- Decision ----

// qRadiusView is what an answer is decided from, swapped whole on every
// save of the state, never locked.
type qRadiusView struct {
	listen   bool // the RADIUS layer is set up: answer access points
	enabled  bool // the quarantine is on: enforce (off: accept everyone)
	approved map[string]bool
	pause    QPause
	secret   []byte
}

var qRadiusSnap atomic.Pointer[qRadiusView]

// qRadiusRefresh publishes the state's decision view. Called with the
// state just saved (under qMu); a failed unseal leaves RADIUS refusing
// every request rather than guessing.
func qRadiusRefresh(st *qState) {
	v := &qRadiusView{listen: st.Radius.Enabled, enabled: st.Enabled, approved: map[string]bool{}, pause: st.Pause}
	for m := range st.Approved {
		v.approved[m] = true
	}
	if st.Radius.Secret != "" {
		if s, err := unsealSecret(qRadiusSecretField, st.Radius.Secret); err == nil {
			v.secret = []byte(s)
		}
	}
	qRadiusSnap.Store(v)
}

type qRadiusVerdict struct {
	accept bool
	learn  bool   // approve it (a learning pause)
	record bool   // record it as waiting for approval
	why    string // for the log and the panel
}

// qRadiusDecide answers for one MAC. Pure.
func qRadiusDecide(v *qRadiusView, mac string, now time.Time) qRadiusVerdict {
	switch {
	case !v.enabled:
		// Access points still set to ask must keep letting devices in
		// while the quarantine is off.
		return qRadiusVerdict{accept: true, why: "the quarantine is off"}
	case v.approved[mac]:
		return qRadiusVerdict{accept: true, why: "approved"}
	case v.pause.active(now) && v.pause.Kind == "learn":
		return qRadiusVerdict{accept: true, learn: true, why: "learning pause"}
	case v.pause.active(now) && v.pause.Kind == "off":
		return qRadiusVerdict{accept: true, record: true, why: "protection paused"}
	}
	return qRadiusVerdict{record: true, why: "not approved"}
}

// qMLOPartner returns the approved MAC that differs from mac only by one in
// the last octet, when there is exactly one: a Wi-Fi 7 device's RADIUS and
// data addresses (E1). Pure.
func qMLOPartner(mac string, approved map[string]bool) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	found := ""
	for _, d := range []int{-1, 1} {
		last := int(hw[5]) + d
		if last < 0 || last > 255 {
			continue
		}
		cand := append(net.HardwareAddr(nil), hw...)
		cand[5] = byte(last)
		if approved[cand.String()] {
			if found != "" {
				return "" // ambiguous: never guess
			}
			found = cand.String()
		}
	}
	return found
}

// ---- Server ----

// QRadiusStats is the panel's health view.
type QRadiusStats struct {
	Listening   bool     `json:"listening"`
	Error       string   `json:"error,omitempty"`
	LastRequest int64    `json:"last_request,omitempty"`
	Accepted    int64    `json:"accepted"`
	Rejected    int64    `json:"rejected"`
	BadAuth     int64    `json:"bad_auth"`
	Clients     []string `json:"clients"` // access point addresses seen
	SSIDs       []string `json:"ssids"`   // SSIDs seen in requests
}

type qRadiusEvent struct {
	mac, ssid string
	learn     bool
	accepted  bool
	at        time.Time
}

var (
	qRadiusMu      sync.Mutex
	qRadiusStats   = QRadiusStats{}
	qRadiusClients = map[string]bool{}
	qRadiusSSIDs   = map[string]bool{}
	qRadiusEvents  = make(chan qRadiusEvent, 256)
	// qRadiusAccepted remembers recent accepts, to pair a Wi-Fi 7 device's
	// data address with its RADIUS address (qRecordSeen).
	qRadiusAccepted = map[string]time.Time{}
	// Recent answers, resent for a retransmitted request (RFC 2865 2.5).
	qRadiusDupes = map[string]qRadiusDupe{}
)

type qRadiusDupe struct {
	resp []byte
	at   time.Time
}

// qRadiusHandle answers one datagram (nil: drop it). It never takes qMu.
func qRadiusHandle(b []byte, from string, now time.Time) []byte {
	v := qRadiusSnap.Load()
	if v == nil || len(v.secret) == 0 {
		return nil
	}
	p, err := parseRadius(b)
	if err != nil || p.code != radiusAccessRequest {
		return nil
	}
	if !verifyRequestAuth(p, v.secret) {
		qRadiusMu.Lock()
		qRadiusStats.BadAuth++
		qRadiusMu.Unlock()
		return nil
	}
	key := from + "/" + hex.EncodeToString(append([]byte{p.id}, p.auth[:]...))
	qRadiusMu.Lock()
	for k, d := range qRadiusDupes {
		if now.Sub(d.at) > 30*time.Second {
			delete(qRadiusDupes, k)
		}
	}
	if d, ok := qRadiusDupes[key]; ok {
		qRadiusMu.Unlock()
		return d.resp
	}
	qRadiusMu.Unlock()

	calling, _ := p.attr(radAttrCallingStation)
	mac := radiusMAC(string(calling))
	if mac == "" {
		user, _ := p.attr(radAttrUserName)
		mac = radiusMAC(string(user))
	}
	called, _ := p.attr(radAttrCalledStation)
	ssid := radiusSSID(string(called))
	if mac == "" {
		return buildRadiusResponse(radiusAccessReject, p, v.secret, []radiusAttr{{typ: radAttrReplyMessage, value: []byte("no device address")}})
	}
	verdict := qRadiusDecide(v, mac, now)
	code := byte(radiusAccessReject)
	if verdict.accept {
		code = radiusAccessAccept
	}
	resp := buildRadiusResponse(code, p, v.secret, nil)

	host, _, _ := net.SplitHostPort(from)
	qRadiusMu.Lock()
	qRadiusDupes[key] = qRadiusDupe{resp: resp, at: now}
	qRadiusStats.LastRequest = now.Unix()
	if verdict.accept {
		qRadiusStats.Accepted++
		qRadiusAccepted[mac] = now
	} else {
		qRadiusStats.Rejected++
	}
	if host != "" && len(qRadiusClients) < 64 {
		qRadiusClients[host] = true
	}
	if ssid != "" && len(qRadiusSSIDs) < 32 {
		qRadiusSSIDs[ssid] = true
	}
	qRadiusMu.Unlock()

	if verdict.learn || verdict.record {
		select {
		case qRadiusEvents <- qRadiusEvent{mac: mac, ssid: ssid, learn: verdict.learn, accepted: verdict.accept, at: now}:
		default: // a flood: the answers matter, the bookkeeping can drop
		}
	}
	return resp
}

// qRadiusRecordLoop applies queued refusals and learned approvals under
// qMu, away from the answers.
func qRadiusRecordLoop() {
	for e := range qRadiusEvents {
		qRadiusRecord(e)
	}
}

// qRadiusRecord records one refused device (waiting for approval, with a
// Wi-Fi 7 hint) or approves one let in by a learning pause.
func qRadiusRecord(e qRadiusEvent) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return
	}
	urgent, routine := qRecordSeenFrom(st, []qElem{{Val: e.mac}}, e.at, false)
	if p, ok := st.Pending[e.mac]; ok {
		if partner := qMLOPartner(e.mac, qApprovedSet(st)); partner != "" && p.PairOf != partner {
			p.PairOf = partner
			st.Pending[e.mac] = p
			routine = true
		}
	}
	switch {
	case urgent:
		if err := qChangeLocked(st); err != nil {
			log.Printf("netgrip: quarantine RADIUS: saving %s: %v", e.mac, err)
		}
	case routine:
		saveQStateLazy(st)
	}
}

// qMLOWindow is how soon after a RADIUS accept the device's data address
// is expected.
const qMLOWindow = time.Minute

// qMLOFromRadius returns the approved RADIUS address a new data address
// belongs to: accepted within qMLOWindow, one apart in the last octet, and
// the only such candidate.
func qMLOFromRadius(mac string, now time.Time, st *qState) string {
	qRadiusMu.Lock()
	recent := map[string]bool{}
	for x, at := range qRadiusAccepted {
		if now.Sub(at) > qMLOWindow {
			delete(qRadiusAccepted, x)
			continue
		}
		if _, ok := st.Approved[x]; ok {
			recent[x] = true
		}
	}
	qRadiusMu.Unlock()
	if len(recent) == 0 {
		return ""
	}
	return qMLOPartner(mac, recent)
}

func qApprovedSet(st *qState) map[string]bool {
	out := map[string]bool{}
	for m := range st.Approved {
		out[m] = true
	}
	return out
}

// qRadiusListenFn opens the socket; a var so tests never bind a port.
var qRadiusListenFn = func() (net.PacketConn, error) {
	return net.ListenPacket("udp", fmt.Sprintf(":%d", qRadiusPort))
}

var qRadiusOnce sync.Once

// StartQuarantineRadius runs the RADIUS listener. It is started before the
// slower services, from the state on disk, so a restart of NetGrip keeps
// access points waiting as briefly as possible; it listens only while the
// layer is on.
func StartQuarantineRadius() {
	qRadiusOnce.Do(func() {
		qMu.Lock()
		qRadiusRefresh(loadQState())
		qMu.Unlock()
		go qRadiusRecordLoop()
		go func() {
			var conn net.PacketConn
			for {
				v := qRadiusSnap.Load()
				want := v != nil && v.listen && len(v.secret) > 0
				switch {
				case want && conn == nil:
					c, err := qRadiusListenFn()
					qRadiusMu.Lock()
					if err != nil {
						qRadiusStats.Listening, qRadiusStats.Error = false, err.Error()
					} else {
						qRadiusStats.Listening, qRadiusStats.Error = true, ""
						conn = c
						go qRadiusServe(c)
					}
					qRadiusMu.Unlock()
				case !want && conn != nil:
					_ = conn.Close()
					conn = nil
					qRadiusMu.Lock()
					qRadiusStats.Listening = false
					qRadiusMu.Unlock()
				}
				time.Sleep(time.Second)
			}
		}()
	})
}

func qRadiusServe(c net.PacketConn) {
	buf := make([]byte, radiusMaxLen)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		if resp := qRadiusHandle(buf[:n], addr.String(), time.Now()); resp != nil {
			_, _ = c.WriteTo(resp, addr)
		}
	}
}

// QuarantineRadiusStats is the health view for the panel.
func QuarantineRadiusStats() QRadiusStats {
	qRadiusMu.Lock()
	defer qRadiusMu.Unlock()
	s := qRadiusStats
	s.Clients, s.SSIDs = []string{}, []string{}
	for c := range qRadiusClients {
		s.Clients = append(s.Clients, c)
	}
	for x := range qRadiusSSIDs {
		s.SSIDs = append(s.SSIDs, x)
	}
	sort.Strings(s.Clients)
	sort.Strings(s.SSIDs)
	return s
}

// qZoneAddresses lists the router's IPv4 addresses on the networks of the
// given zones (without the prefix length).
func qZoneAddresses(zones []QZone, names []string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	nets := map[string]bool{}
	for _, z := range zones {
		if want[z.Name] {
			for _, n := range z.Networks {
				nets[n] = true
			}
		}
	}
	out := []string{}
	ifaces, _ := dumpInterfacesFn()
	for _, i := range ifaces {
		if !nets[i.Name] {
			continue
		}
		for _, a := range i.IPv4 {
			ip, _, _ := strings.Cut(a, "/")
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// quarantineRadiusBackupInfo is what the monitoring server needs to answer
// RADIUS while this panel cannot: read from the answers' snapshot, never
// waiting for the quarantine's lock. nil while the RADIUS layer is off.
func quarantineRadiusBackupInfo() *probe.QuarantineRadiusInfo {
	v := qRadiusSnap.Load()
	if v == nil || !v.listen || len(v.secret) == 0 {
		return nil
	}
	info := &probe.QuarantineRadiusInfo{Secret: string(v.secret), Enforce: v.enabled, Approved: make([]string, 0, len(v.approved))}
	for m := range v.approved {
		info.Approved = append(info.Approved, m)
	}
	sort.Strings(info.Approved)
	if v.pause.Until > time.Now().Unix() {
		info.PauseUntil, info.PauseKind = v.pause.Until, v.pause.Kind
	}
	return info
}

// ---- Turning it on and off ----

// qNewRadiusSecret makes a 24-character secret from an alphabet any access
// point's form accepts.
func qNewRadiusSecret() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// qRadiusRuleOps writes (zones non-empty) or removes the firewall rule
// admitting RADIUS from the access points' zones.
func qRadiusRuleOps(fw map[string]uciSection, zones []string) []executor.Op {
	var ops []executor.Op
	if len(zones) == 0 {
		deleteSections(&ops, fw, "firewall", func(n string) bool { return n == qRadiusRule })
	} else {
		ensureSection(&ops, fw, "firewall", qRadiusRule, "rule", map[string][]string{
			"name": {"netgrip quarantine: RADIUS from the access points"}, "src": {strings.Join(zones, " ")},
			"proto": {"udp"}, "dest_port": {fmt.Sprint(qRadiusPort)}, "target": {"ACCEPT"},
		})
	}
	if len(ops) == 0 {
		return nil
	}
	return append(ops, executor.Op{Kind: "uci_commit", Args: []string{"firewall"}},
		executor.Op{Kind: "initd", Args: []string{"firewall", "reload"}})
}

// QuarantineRadiusEnable turns the RADIUS layer on for access points in
// the given zones. It only adds a firewall rule that admits more, so no
// confirm window is needed; joining stays unchanged until the access point
// is set to ask.
func QuarantineRadiusEnable(zones []string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if !st.Enabled {
		return probeQuarantineLocked(), errors.New("turn the quarantine on first")
	}
	r, err := readQRouter()
	if err != nil {
		return probeQuarantineLocked(), err
	}
	known := map[string]bool{}
	for _, z := range r.zones {
		known[z.Name] = !z.Wan
	}
	if len(zones) == 0 {
		return probeQuarantineLocked(), errors.New("choose the zone your access points are in")
	}
	for _, z := range zones {
		if !known[z] || !reZoneName.MatchString(z) {
			return probeQuarantineLocked(), fmt.Errorf("unknown zone %q", z)
		}
	}
	sort.Strings(zones)
	if st.Radius.Secret == "" {
		secret, err := qNewRadiusSecret()
		if err != nil {
			return probeQuarantineLocked(), err
		}
		sealed, err := sealSecret(qRadiusSecretField, secret)
		if err != nil {
			return probeQuarantineLocked(), fmt.Errorf("sealing the RADIUS secret: %w", err)
		}
		st.Radius.Secret = sealed
	}
	if err := QuarantinePendingCheck([]string{"firewall"}); err != nil {
		return probeQuarantineLocked(), err
	}
	fw, err := uciShowFn("firewall")
	if err != nil {
		return probeQuarantineLocked(), err
	}
	if ops := qRadiusRuleOps(parseUCIShow(fw, "firewall"), zones); ops != nil {
		if err := applyQWifiOps(ops); err != nil {
			return probeQuarantineLocked(), fmt.Errorf("adding the firewall rule for RADIUS: %w", err)
		}
	}
	st.Radius.Enabled, st.Radius.Zones = true, zones
	if err := saveQState(st); err != nil {
		return probeQuarantineLocked(), err
	}
	log.Printf("netgrip: quarantine RADIUS layer on (zones %s)", strings.Join(zones, ","))
	return probeQuarantineLocked(), nil
}

// QuarantineRadiusDisable turns it off: the server stops answering (an
// access point still set to ask then refuses joins: the panel says to turn
// MAC authentication off there first) and the firewall rule goes. Turning
// the quarantine off does not do this: RADIUS then accepts everyone.
func QuarantineRadiusDisable() (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if err := qRadiusTeardownLocked(st); err != nil {
		return probeQuarantineLocked(), err
	}
	_ = saveQState(st)
	log.Printf("netgrip: quarantine RADIUS layer off")
	return probeQuarantineLocked(), nil
}

func qRadiusTeardownLocked(st *qState) error {
	fw, err := uciShowFn("firewall")
	if err != nil {
		return err
	}
	if ops := qRadiusRuleOps(parseUCIShow(fw, "firewall"), nil); ops != nil {
		if err := QuarantinePendingCheck([]string{"firewall"}); err != nil {
			return err
		}
		if err := applyQWifiOps(ops); err != nil {
			return fmt.Errorf("removing the firewall rule for RADIUS: %w", err)
		}
	}
	st.Radius.Enabled = false
	return nil
}

// QuarantineRadiusSecret reveals the secret, to paste into the access
// point's RADIUS profile.
func QuarantineRadiusSecret() (string, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if st.Radius.Secret == "" {
		return "", errors.New("no RADIUS secret yet: turn the layer on first")
	}
	return unsealSecret(qRadiusSecretField, st.Radius.Secret)
}

// QuarantineRadiusNewSecret replaces the secret (the access point's profile
// must then be updated, or every join is refused).
func QuarantineRadiusNewSecret() (string, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	secret, err := qNewRadiusSecret()
	if err != nil {
		return "", err
	}
	sealed, err := sealSecret(qRadiusSecretField, secret)
	if err != nil {
		return "", err
	}
	st.Radius.Secret = sealed
	if err := saveQState(st); err != nil {
		return "", err
	}
	return secret, nil
}
