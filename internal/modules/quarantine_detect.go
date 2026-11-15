package modules

// Copied-MAC detection (quarantine phase 5).
//
// The quarantine trusts a MAC address, and a MAC is easy to copy: anyone in
// range sees the approved ones in the air. Each approved device gets an
// identity profile (how it asks for an address, its hostname, the addresses
// it uses, where it is); a device that later shows up with a value its
// profile never had is reported.
//
// Every value of a signal is learned silently for qDetectLearn after the
// profile starts; after that a new value is a signal, and the profile keeps
// up to qProfileHistory values per signal, so a device that goes back and
// forth between known states is not flagged. "Same device" in the panel
// adds the reported values to the profile.
//
// Strong signals, or two different signals within qDetectWindow, make an
// alert; a single medium one makes a notice. Optionally (QDetect.Auto) an
// alert moves the device back to quarantine, never for a device that opened
// the panel recently or an access point, and never when many devices change
// at once (that is the router's doing, not a copy).

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
)

const (
	qDetectLearn    = 24 * time.Hour
	qDetectWindow   = time.Hour
	qProfileHistory = 4
	qMaxSignals     = 12
	qMaxValueLen    = 128
	// qSuspectTTL: a report nobody acted on and that saw nothing new is
	// dropped after this long.
	qSuspectTTL = 30 * 24 * time.Hour
	// qNotifyGap: at most one message per device in this time.
	qNotifyGap = 10 * time.Minute
	// qMassChange: this many devices reported in one check is a change on
	// the router side (a DHCP option, a firmware update): one summary, no
	// automatic action.
	qMassChange = 8
	// qRoamWindow, qRoamFlips: a device answered by access points A, B, A,
	// B within the window is in two places, or flapping.
	qRoamWindow = 2 * time.Minute
	qRoamFlips  = 3
	// qViewerTTL: a device that opened the panel this recently is never
	// moved automatically (it would cut off the user).
	qViewerTTL = 30 * 24 * time.Hour
	// qMassWindow: reports of this many minutes count together for
	// qMassChange (devices reconnect over minutes after a router change).
	qMassWindow = 10 * time.Minute
	// qPlacesHold: "several networks at once" must last this long (a
	// neighbour stays REACHABLE for up to ~45 s after a device moves).
	qPlacesHold = time.Minute
	// qUnleasedUptime: an address with no lease at all is only reported
	// once the router has been up this long (/tmp's leases are lost on a
	// reboot, and devices renew within half their lease time).
	qUnleasedUptime = 24 * time.Hour
	// qSuspectRefresh: a report that is still there is touched (and the
	// state written) at most this often.
	qSuspectRefresh = time.Hour
)

// Signal kinds. Strong ones alone make an alert.
const (
	qSigDHCP     = "dhcp"     // DHCP option 55 (the requested-options list)
	qSigVendor   = "vendor"   // DHCP option 60 (vendor class)
	qSigHostname = "hostname" // DHCP hostname
	qSigClientID = "clientid" // DHCP client identifier
	qSigIP       = "ip"       // uses an address it was not given
	qSigPlaces   = "places"   // active on several networks at once
	qSigRadio    = "radio"    // Wi-Fi capabilities (router SSIDs)
	qSigRoam     = "roam"     // alternating between two access points
	qSigURadio   = "uradio"   // Wi-Fi in use on a UniFi access point (via NetPulse)
	qSigMedium   = "medium"   // wired or Wi-Fi, as UniFi sees it (via NetPulse)
	qLeasedMark  = "leased"   // profile only: the device has used DHCP
)

func qSignalStrong(kind string) bool { return kind == qSigDHCP || kind == qSigPlaces }

// QDetect is the feature's state.
type QDetect struct {
	Enabled  bool                 `json:"enabled"`
	Auto     bool                 `json:"auto,omitempty"`
	Profiles map[string]*QProfile `json:"profiles,omitempty"`
	Suspects map[string]*QSuspect `json:"suspects,omitempty"`
	// Viewers: devices that opened the panel (when), and Infra: access
	// points that asked RADIUS (when). Kept across restarts: the automatic
	// action never moves them.
	Viewers map[string]int64 `json:"viewers,omitempty"`
	Infra   map[string]int64 `json:"infra,omitempty"`
}

// QProfile is one approved device's identity.
type QProfile struct {
	Since int64 `json:"since"`
	// Values: the known values of each signal, newest first.
	Values map[string][]string `json:"values,omitempty"`
	// FPAt: the time of the last fingerprint line taken in.
	FPAt int64 `json:"fp_at,omitempty"`
}

// QSignal is one piece of evidence.
type QSignal struct {
	Kind   string   `json:"kind"`
	Strong bool     `json:"strong,omitempty"`
	Was    []string `json:"was,omitempty"`
	Now    string   `json:"now"`
	First  int64    `json:"first"`
	Last   int64    `json:"last"`
	// Dismissed: the user dismissed the report while this was in it: it no
	// longer counts towards an alert or the automatic action.
	Dismissed bool `json:"dismissed,omitempty"`
}

// QSuspect is a device reported as possibly copied.
type QSuspect struct {
	Signals  []QSignal `json:"signals"`
	Level    string    `json:"level"` // "notice" or "alert"
	First    int64     `json:"first"`
	Last     int64     `json:"last"`
	Notified int64     `json:"notified,omitempty"`
	// NotifiedSig: how many signals the last message covered.
	NotifiedSig int    `json:"notified_sig,omitempty"`
	NotifiedLvl string `json:"notified_lvl,omitempty"`
	// Action: "quarantined" when it was moved back automatically.
	Action   string `json:"action,omitempty"`
	ActionAt int64  `json:"action_at,omitempty"`
	// Dismissed: the user dismissed it; the same evidence stays quiet and
	// only a new signal opens it again.
	Dismissed int64 `json:"dismissed,omitempty"`
}

// QDetectProbe is the feature for the panel.
type QDetectProbe struct {
	Enabled bool `json:"enabled"`
	Auto    bool `json:"auto"`
	// Learning: approved devices still in their first qDetectLearn;
	// LearnUntil: when the last of them is done.
	Learning   int           `json:"learning"`
	LearnUntil int64         `json:"learn_until,omitempty"`
	Profiles   int           `json:"profiles"`
	Suspects   []QSuspectRow `json:"suspects"`
	// Sources: what this router can see ("fingerprints", "leases",
	// "neighbours", "stations", "radius", "unifi").
	Sources []string `json:"sources"`
}

// QSuspectRow is a report for the panel.
type QSuspectRow struct {
	QDevice
	QSuspect
}

// ---- Observation ----

// qObs is what one check saw, per MAC (lowercase).
type qObs struct {
	fp       map[string]qFP
	leases   map[string][]ubus.Lease
	leasesOK bool
	neigh    map[string][]qNeigh // REACHABLE only
	all      []qNeighEntry       // every state (to find access points)
	neighOK  bool
	// uptimeOK: the router has been up qUnleasedUptime.
	uptimeOK bool
	radio    map[string]string // mac -> "band:flags"
	radioOK  bool
	// unifi: what NetPulse's UniFi controller says, per MAC (when its
	// last answer is recent).
	unifi   map[string]qUnifiObs
	roam    map[string][]qRoamHit
	sources []string
}

type qFP struct {
	opts, vendor string
	at           int64
}

type qNeigh struct{ ip, dev string }

type qRoamHit struct {
	ap string
	at time.Time
}

var (
	qFingerprintPath = "/tmp/netpulse-agent/dhcp-fingerprints"
	qLeasesPath      = "/tmp/dhcp.leases"
)

// qReadFingerprints reads the DHCP hook's file: mac, option 55, option 60,
// time, tab-separated (written by /etc/hotplug.d/dhcp/50-netpulse-agent).
var qReadFingerprints = func() (map[string]qFP, bool) {
	b, err := os.ReadFile(qFingerprintPath)
	if err != nil {
		return nil, false
	}
	return qParseFingerprints(string(b)), true
}

func qParseFingerprints(s string) map[string]qFP {
	out := map[string]qFP{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue // a half-written line
		}
		mac := strings.ToLower(strings.TrimSpace(f[0]))
		at, err := strconv.ParseInt(strings.TrimSpace(f[3]), 10, 64)
		if !reMac.MatchString(mac) || err != nil {
			continue
		}
		fp := qFP{opts: strings.TrimSpace(f[1]), vendor: strings.TrimSpace(f[2]), at: at}
		if fp.opts == "" && fp.vendor == "" {
			continue
		}
		out[mac] = fp
	}
	return out
}

// qReadLeases reads dnsmasq's leases (only where this router serves DHCP).
var qReadLeases = func() ([]ubus.Lease, bool) {
	if _, err := os.Stat(qLeasesPath); err != nil {
		return nil, false
	}
	l, err := ubus.ReadLeases(qLeasesPath)
	return l, err == nil
}

// qReadNeighbours lists the IPv4 neighbours that answered within the last
// seconds (REACHABLE): a device active right now, and where.
var qReadNeighbours = func() ([]qNeighEntry, bool) {
	out, err := exec.Command("ip", "-4", "neigh", "show").Output()
	if err != nil {
		return nil, false
	}
	return qParseNeighbours(string(out)), true
}

type qNeighEntry struct{ ip, dev, mac, state string }

func qParseNeighbours(s string) []qNeighEntry {
	var out []qNeighEntry
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		e := qNeighEntry{ip: f[0], state: f[len(f)-1]}
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				e.dev = f[i+1]
			case "lladdr":
				e.mac = strings.ToLower(f[i+1])
			}
		}
		if e.dev != "" && reMac.MatchString(e.mac) && net.ParseIP(e.ip) != nil {
			out = append(out, e)
		}
	}
	return out
}

// qReadStations maps the router's own Wi-Fi clients to their capabilities
// per band ("5g:eht,he,mfp,vht"): hostapd's client list.
var qReadStations = func() (map[string]string, bool) {
	objs, err := ubus.ListObjects("hostapd.")
	if err != nil || len(objs) == 0 {
		return nil, false
	}
	out := map[string]string{}
	for _, o := range objs {
		raw, err := ubus.Call(o, "get_clients")
		if err != nil {
			continue
		}
		var p struct {
			Freq    int                       `json:"freq"`
			Clients map[string]map[string]any `json:"clients"`
		}
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		for mac, c := range p.Clients {
			if sig := qRadioSignature(p.Freq, c); sig != "" {
				out[strings.ToLower(mac)] = sig
			}
		}
	}
	return out, true
}

func qRadioSignature(freq int, c map[string]any) string {
	band := ""
	switch {
	case freq <= 0:
		return ""
	case freq < 3000:
		band = "2g"
	case freq < 5925:
		band = "5g"
	default:
		band = "6g"
	}
	var flags []string
	for _, k := range []string{"ht", "vht", "he", "eht", "mfp", "wmm"} {
		if v, ok := c[k].(bool); ok && v {
			flags = append(flags, k)
		}
	}
	sort.Strings(flags)
	return band + ":" + strings.Join(flags, ",")
}

// RADIUS access-point history of approved devices (fed by qRadiusHandle).
var (
	qRoamMu sync.Mutex
	qRoam   = map[string][]qRoamHit{}
)

// qNoteRoam records which access point (its address) asked about an
// approved device.
func qNoteRoam(mac, ap string, now time.Time) {
	if ap == "" {
		return
	}
	qRoamMu.Lock()
	defer qRoamMu.Unlock()
	h := qRoam[mac]
	kept := h[:0]
	for _, x := range h {
		if now.Sub(x.at) <= qRoamWindow {
			kept = append(kept, x)
		}
	}
	if len(kept) == 0 && len(qRoam) >= 1024 {
		for m, hs := range qRoam {
			if len(hs) == 0 || now.Sub(hs[len(hs)-1].at) > qRoamWindow {
				delete(qRoam, m)
			}
		}
		if len(qRoam) >= 1024 {
			return
		}
	}
	if len(kept) >= 8 {
		kept = kept[1:]
	}
	qRoam[mac] = append(kept, qRoamHit{ap: ap, at: now})
}

func qRoamSnapshot(now time.Time) map[string][]qRoamHit {
	qRoamMu.Lock()
	defer qRoamMu.Unlock()
	out := map[string][]qRoamHit{}
	for m, h := range qRoam {
		var kept []qRoamHit
		for _, x := range h {
			if now.Sub(x.at) <= qRoamWindow {
				kept = append(kept, x)
			}
		}
		if len(kept) > 0 {
			out[m] = kept
		} else {
			delete(qRoam, m)
		}
	}
	return out
}

// qRoamFlipping returns "A ↔ B" when the hits go back and forth between two
// access points at least qRoamFlips times (A B A B), else "".
func qRoamFlipping(h []qRoamHit) string {
	var seq []string
	for _, x := range h {
		if len(seq) == 0 || seq[len(seq)-1] != x.ap {
			seq = append(seq, x.ap)
		}
	}
	if len(seq) < qRoamFlips+1 {
		return ""
	}
	aps := map[string]bool{}
	for _, a := range seq {
		aps[a] = true
	}
	if len(aps) != 2 {
		return "" // a walk through several access points is roaming
	}
	pair := []string{seq[0], seq[1]}
	sort.Strings(pair)
	return pair[0] + " ↔ " + pair[1]
}

// Devices that opened the panel recently (memory only), and when each
// address was last looked up.
var (
	qViewersMu  sync.Mutex
	qViewers    = map[string]time.Time{}
	qViewerIPAt = map[string]time.Time{}
)

// QuarantineNoteViewer remembers the device behind a signed-in panel
// request, so the automatic action never cuts off the user. Each address
// is looked up at most once a minute.
func QuarantineNoteViewer(ip string) {
	now := time.Now()
	qViewersMu.Lock()
	if at, ok := qViewerIPAt[ip]; ok && now.Sub(at) < time.Minute {
		qViewersMu.Unlock()
		return
	}
	if len(qViewerIPAt) >= 256 {
		qViewerIPAt = map[string]time.Time{}
	}
	qViewerIPAt[ip] = now
	qViewersMu.Unlock()
	mac := requesterMACFn(ip)
	if mac == "" {
		return
	}
	qViewersMu.Lock()
	defer qViewersMu.Unlock()
	if len(qViewers) < 256 {
		qViewers[mac] = now
	}
}

// qTakeViewers returns the devices noted since the last call.
func qTakeViewers() map[string]time.Time {
	qViewersMu.Lock()
	defer qViewersMu.Unlock()
	out := qViewers
	qViewers = map[string]time.Time{}
	return out
}

// qInfrastructure: the MACs of the access points that ask RADIUS (their
// addresses, through the neighbour table, in any state).
func qInfrastructure(neigh []qNeighEntry) map[string]bool {
	qRadiusMu.Lock()
	hosts := map[string]bool{}
	for h := range qRadiusClients {
		hosts[h] = true
	}
	qRadiusMu.Unlock()
	out := map[string]bool{}
	for _, n := range neigh {
		if hosts[n.ip] {
			out[n.mac] = true
		}
	}
	return out
}

var qObserveFn = qObserve

// qUptimeFn: how long the router has been up.
var qUptimeFn = func() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	s, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(s * float64(time.Second))
}

func qObserve(now time.Time) qObs {
	o := qObs{leases: map[string][]ubus.Lease{}, neigh: map[string][]qNeigh{}}
	o.uptimeOK = qUptimeFn() >= qUnleasedUptime
	if fp, ok := qReadFingerprints(); ok {
		o.fp = fp
		o.sources = append(o.sources, "fingerprints")
	}
	if l, ok := qReadLeases(); ok {
		o.leasesOK = true
		o.sources = append(o.sources, "leases")
		for _, x := range l {
			m := strings.ToLower(x.MAC)
			o.leases[m] = append(o.leases[m], x) // one per network it uses
		}
	}
	if n, ok := qReadNeighbours(); ok {
		o.neighOK = true
		o.sources = append(o.sources, "neighbours")
		o.all = n
		for _, e := range n {
			if e.state == "REACHABLE" {
				o.neigh[e.mac] = append(o.neigh[e.mac], qNeigh{ip: e.ip, dev: e.dev})
			}
		}
	}
	if r, ok := qReadStations(); ok {
		o.radio, o.radioOK = r, true
		o.sources = append(o.sources, "stations")
	}
	if v := qRadiusSnap.Load(); v != nil && v.listen {
		o.roam = qRoamSnapshot(now)
		o.sources = append(o.sources, "radius")
	}
	if u, ok := qStationsSnapshot(now); ok {
		o.unifi = u
		o.sources = append(o.sources, "unifi")
	}
	return o
}

// ---- Decision ----

// qObserved returns each signal's current value for one device (kind ->
// values; one value for most kinds, several for ip).
func qObserved(mac string, p *QProfile, o qObs) map[string][]string {
	out := map[string][]string{}
	add := func(kind, v string) {
		if v = qCleanText(v, qMaxValueLen); v != "" {
			out[kind] = append(out[kind], v)
		}
	}
	if fp, ok := o.fp[mac]; ok && fp.at > p.FPAt {
		add(qSigDHCP, fp.opts)
		add(qSigVendor, fp.vendor)
	}
	for _, l := range o.leases[mac] {
		if l.Hostname != "*" {
			add(qSigHostname, l.Hostname)
		}
		if l.ClientID != "*" {
			add(qSigClientID, l.ClientID)
		}
		add(qLeasedMark, "yes")
	}
	if ns := o.neigh[mac]; len(ns) > 0 {
		devs := map[string]bool{}
		for _, n := range ns {
			devs[n.dev] = true
			// An address it was not given: it has used DHCP, and this
			// address is not its lease.
			// Self-assigned link-local addresses (169.254/16) are normal.
			if o.leasesOK && !strings.HasPrefix(n.ip, "169.254.") && (len(p.Values[qLeasedMark]) > 0 || len(out[qLeasedMark]) > 0) {
				leased, has := false, len(o.leases[mac]) > 0
				for _, l := range o.leases[mac] {
					leased = leased || l.IP == n.ip
				}
				// No lease at all right after a reboot is normal.
				if !leased && (has || o.uptimeOK) {
					add(qSigIP, n.ip)
				}
			}
		}
		if len(devs) > 1 {
			names := make([]string, 0, len(devs))
			for d := range devs {
				names = append(names, d)
			}
			sort.Strings(names)
			add(qSigPlaces, strings.Join(names, " + "))
		}
	}
	if sig, ok := o.radio[mac]; ok {
		add(qSigRadio, sig)
	}
	if v := qRoamFlipping(o.roam[mac]); v != "" {
		add(qSigRoam, v)
	}
	if u, ok := o.unifi[mac]; ok {
		add(qSigMedium, u.medium)
		add(qSigURadio, u.radio)
	}
	return out
}

// qBanded: kinds whose values are compared per context, the part before
// the first ':' (the band, or the access point model and band): a context
// never seen before is learned, not reported, and keeps more history.
func qBanded(kind string) bool { return kind == qSigRadio || kind == qSigURadio }

func qContext(v string) string { return strings.SplitN(v, ":", 2)[0] }

// qBandedMax bounds a per-context kind's values over all its contexts
// (qProfileHistory per context).
const qBandedMax = 32

func qKnown(p *QProfile, kind, v string) bool {
	if qBanded(kind) {
		// Capabilities are compared per band (VHT only exists on 5 GHz),
		// and on UniFi per access point model too (an older one offers
		// an older standard).
		band := qContext(v)
		seen := false
		for _, x := range p.Values[kind] {
			if qContext(x) == band {
				seen = true
				if x == v {
					return true
				}
			}
		}
		return !seen // a band never seen before is learned, not reported
	}
	for _, x := range p.Values[kind] {
		if x == v {
			return true
		}
	}
	return false
}

func qLearnValue(p *QProfile, kind, v string) bool {
	if qKnown(p, kind, v) && (!qBanded(kind) || qHas(p.Values[kind], v)) {
		return false
	}
	list := []string{v}
	if qBanded(kind) {
		// qProfileHistory per context, so a context seen often does not
		// push out the others.
		per := map[string]int{qContext(v): 1}
		for _, x := range p.Values[kind] {
			if x != v && per[qContext(x)] < qProfileHistory && len(list) < qBandedMax {
				per[qContext(x)]++
				list = append(list, x)
			}
		}
		if p.Values == nil {
			p.Values = map[string][]string{}
		}
		p.Values[kind] = list
		return true
	}
	for _, x := range p.Values[kind] {
		if x != v && len(list) < qProfileHistory {
			list = append(list, x)
		}
	}
	if p.Values == nil {
		p.Values = map[string][]string{}
	}
	p.Values[kind] = list
	return true
}

func qHas(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// qSource groups kinds that come from one observation: the DHCP
// fingerprint and vendor class are one request (an OS update changes both),
// and what NetPulse relays from UniFi is one source however many things it
// says (it must not make an alert, or the automatic move, on its own).
func qSource(kind string) string {
	switch kind {
	case qSigVendor:
		return qSigDHCP
	case qSigMedium:
		return qSigURadio
	}
	return kind
}

// qOwnSignals: the signals this router saw itself, without what NetPulse
// relays from UniFi. Only these count towards the automatic move: UniFi's
// view changes with the same association events as the access points'
// RADIUS requests ("roam"), so one physical event could look like two
// sources.
func qOwnSignals(sigs []QSignal) []QSignal {
	var out []QSignal
	for _, s := range sigs {
		if qSource(s.Kind) != qSigURadio {
			out = append(out, s)
		}
	}
	return out
}

// qActive: the signals that count (not dismissed).
func qActive(sigs []QSignal) []QSignal {
	var out []QSignal
	for _, s := range sigs {
		if !s.Dismissed {
			out = append(out, s)
		}
	}
	return out
}

// qLevel: an alert for a strong signal, or two sources that started within
// qDetectWindow of each other. Dismissed signals do not count.
func qLevel(sigs []QSignal) string {
	sigs = qActive(sigs)
	for _, a := range sigs {
		if a.Strong {
			return "alert"
		}
	}
	if qKinds(sigs) >= 2 {
		return "alert"
	}
	return "notice"
}

// qKinds: the most sources whose signals started within qDetectWindow of
// one another (an old signal that is still there does not pair with a
// later change). Dismissed signals do not count.
func qKinds(sigs []QSignal) int {
	sigs = qActive(sigs)
	best := 0
	for _, a := range sigs {
		src := map[string]bool{}
		for _, b := range sigs {
			gap := b.First - a.First
			if gap >= 0 && gap <= int64(qDetectWindow/time.Second) {
				src[qSource(b.Kind)] = true
			}
		}
		if len(src) > best {
			best = len(src)
		}
	}
	return best
}

// In memory: when each "several networks" value was first seen (it must
// last qPlacesHold), the devices reported recently (qMassWindow) and when
// the last summary went out.
var (
	qPlacesSeen = map[string]time.Time{}
	qMassRecent = map[string]time.Time{}
	qMassToldAt time.Time
)

// qDetectLocked runs one check (full checks only). It returns whether the
// approved list changed (an automatic move) and whether anything else did.
func qDetectLocked(st *qState, now time.Time) (urgent, routine bool) {
	d := &st.Detect
	if !d.Enabled {
		return false, false
	}
	for _, m := range []*map[string]int64{&d.Viewers, &d.Infra} {
		if *m == nil {
			*m = map[string]int64{}
		}
	}
	if d.Profiles == nil {
		d.Profiles = map[string]*QProfile{}
	}
	if d.Suspects == nil {
		d.Suspects = map[string]*QSuspect{}
	}
	// Who must never be moved: the panel's devices and the access points,
	// remembered across restarts.
	for mac, at := range qTakeViewers() {
		if d.Viewers[mac] < at.Unix()-3600 || d.Viewers[mac] == 0 {
			d.Viewers[mac] = at.Unix()
			routine = true
		}
	}
	o := qObserveFn(now)
	for mac := range qInfrastructure(o.all) {
		if now.Unix()-d.Infra[mac] > 3600 {
			d.Infra[mac] = now.Unix()
			routine = true
		}
	}
	for _, m := range []map[string]int64{d.Viewers, d.Infra} {
		for mac, at := range m {
			if now.Unix()-at > int64(qViewerTTL/time.Second) {
				delete(m, mac)
				routine = true
			}
		}
		for len(m) > 256 {
			oldest, at := "", int64(0)
			for mac, t := range m {
				if oldest == "" || t < at {
					oldest, at = mac, t
				}
			}
			delete(m, oldest)
		}
	}
	// Profiles follow the approved list.
	for mac := range d.Profiles {
		if _, ok := st.Approved[mac]; !ok {
			delete(d.Profiles, mac)
			routine = true
		}
	}
	for mac, s := range d.Suspects {
		_, approved := st.Approved[mac]
		stale := now.Unix()-s.Last > int64(qSuspectTTL/time.Second)
		// A report goes with its device's approval; one that moved its
		// device back to quarantine stays until it is approved again. If
		// that happens before its profile was dropped, the evidence is
		// learned (the user says it is the same device); otherwise the new
		// profile learns for qDetectLearn.
		if stale || approved == (s.Action != "") {
			if approved && s.Action != "" {
				if p := d.Profiles[mac]; p != nil {
					for _, sig := range s.Signals {
						qLearnValue(p, sig.Kind, sig.Now)
					}
				}
			}
			delete(d.Suspects, mac)
			routine = true
		}
	}
	qDetectSourcesMu.Lock()
	qDetectSources = append([]string(nil), o.sources...)
	qDetectSourcesMu.Unlock()

	placesNow := map[string]bool{}
	var reports []string
	for mac := range st.Approved {
		p := d.Profiles[mac]
		if p == nil {
			p = &QProfile{Since: now.Unix()}
			d.Profiles[mac] = p
			routine = true
		}
		learning := now.Unix()-p.Since < int64(qDetectLearn/time.Second)
		obs := qObserved(mac, p, o)
		if fp, ok := o.fp[mac]; ok && fp.at > p.FPAt {
			p.FPAt = fp.at
			routine = true
		}
		// "Several networks at once" counts only once it has lasted.
		var held []string
		for _, v := range obs[qSigPlaces] {
			k := mac + "|" + v
			placesNow[k] = true
			if first, ok := qPlacesSeen[k]; !ok {
				qPlacesSeen[k] = now
			} else if now.Sub(first) >= qPlacesHold {
				held = append(held, v)
			}
		}
		if held != nil {
			obs[qSigPlaces] = held
		} else {
			delete(obs, qSigPlaces)
		}
		var fresh []QSignal
		kinds := make([]string, 0, len(obs))
		for k := range obs {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			for _, v := range obs[kind] {
				if kind == qLeasedMark || learning || len(p.Values[kind]) == 0 && kind != qSigIP && kind != qSigPlaces && kind != qSigRoam {
					// Learning, or the first value of a signal ever seen
					// (a source that just appeared): learned.
					if qLearnValue(p, kind, v) {
						routine = true
					}
					continue
				}
				if qKnown(p, kind, v) {
					if qBanded(kind) && !qHas(p.Values[kind], v) && qLearnValue(p, kind, v) {
						routine = true // a new band
					}
					continue
				}
				fresh = append(fresh, QSignal{Kind: kind, Strong: qSignalStrong(kind), Was: qWas(p, kind, v), Now: v, First: now.Unix(), Last: now.Unix()})
			}
		}
		if len(fresh) == 0 {
			continue
		}
		s := d.Suspects[mac]
		if s == nil {
			s = &QSuspect{First: now.Unix(), Last: now.Unix()}
			d.Suspects[mac] = s
			routine = true
		}
		added := false
		for _, f := range fresh {
			merged := false
			for i := range s.Signals {
				if s.Signals[i].Kind == f.Kind && s.Signals[i].Now == f.Now {
					if now.Unix()-s.Signals[i].Last >= int64(qSuspectRefresh/time.Second) {
						s.Signals[i].Last = f.Last
						routine = true
					}
					merged = true
					break
				}
			}
			if !merged && len(s.Signals) < qMaxSignals {
				s.Signals = append(s.Signals, f)
				added = true
			}
		}
		if added {
			s.Dismissed = 0 // new evidence opens a dismissed report again
			s.Last = now.Unix()
			routine = true
		} else if now.Unix()-s.Last >= int64(qSuspectRefresh/time.Second) {
			s.Last = now.Unix()
			routine = true
		}
		s.Level = qLevel(s.Signals)
		reports = append(reports, mac)
	}
	for k := range qPlacesSeen {
		if !placesNow[k] {
			delete(qPlacesSeen, k)
		}
	}

	// Messages: when a report is new, rises to an alert or gains evidence,
	// at most once per device per qNotifyGap; never for a dismissed one.
	var tell []string
	for _, mac := range reports {
		s := d.Suspects[mac]
		if s.Action != "" || s.Dismissed != 0 {
			continue
		}
		grew := len(s.Signals) > s.NotifiedSig || (s.Level == "alert" && s.NotifiedLvl != "alert")
		if !grew || now.Unix()-s.Notified < int64(qNotifyGap/time.Second) {
			continue
		}
		tell = append(tell, mac)
	}
	sort.Strings(tell)
	// Many devices within minutes: a change on the router, not copies.
	for mac, at := range qMassRecent {
		if now.Sub(at) > qMassWindow {
			delete(qMassRecent, mac)
		}
	}
	for _, mac := range tell {
		qMassRecent[mac] = now
	}
	mass := len(qMassRecent) >= qMassChange
	var ident *qIdent
	label := func(mac string) string {
		if ident == nil {
			i := qIdentities()
			ident = &i
		}
		dev := ident.device(mac)
		if a := st.Approved[mac]; a.Name != "" {
			dev.Name = a.Name
		}
		return qDeviceLabel(dev)
	}
	protected := qProtected(st)
	var msgs []qDetectMsg
	for _, mac := range tell {
		s := d.Suspects[mac]
		s.Notified, s.NotifiedSig, s.NotifiedLvl = now.Unix(), len(s.Signals), s.Level
		routine = true
		if mass {
			continue
		}
		m := qDetectMsg{mac: mac, label: label(mac), level: s.Level, signals: append([]QSignal(nil), s.Signals...)}
		if d.Auto && s.Level == "alert" {
			switch why := protected(mac); {
			case why != "":
				m.skipped = why
			case qKinds(s.Signals) < 2:
				m.skipped = "one kind of evidence is not enough to move a device automatically (an update can change it)"
			case qKinds(qOwnSignals(s.Signals)) < 2:
				m.skipped = "evidence relayed from UniFi does not move a device automatically"
			default:
				delete(st.Approved, mac)
				delete(st.Notified, mac)
				s.Action, s.ActionAt = "quarantined", now.Unix()
				m.moved = true
				urgent = true
				log.Printf("netgrip: quarantine: %s moved back to quarantine (possible copied MAC)", mac)
			}
		}
		msgs = append(msgs, m)
	}
	if mass && len(tell) > 0 && now.Sub(qMassToldAt) > qMassWindow {
		qMassToldAt = now
		go qNotifyDetect([]qDetectMsg{{}}, len(qMassRecent), qChannelsFn, qNotifyFn)
	}
	if len(msgs) > 0 {
		go qNotifyDetect(msgs, 0, qChannelsFn, qNotifyFn)
	}
	return urgent, routine
}

// qProtected returns why a device must never be moved automatically ("" if
// it may be): a device that opened the panel, the one approved as the
// user's own, an access point, or the other address of any of them (a
// Wi-Fi 7 pair). Until a panel device is known nothing may be moved: it
// could be the user's.
func qProtected(st *qState) func(mac string) string {
	d := st.Detect
	pairs := qPairsOf(st)
	own := func(mac string) string {
		switch {
		case d.Viewers[mac] != 0:
			return "it was used to open this panel"
		case st.Approved[mac].Via == "panel":
			return "it was approved as the device you use for this panel"
		case d.Infra[mac] != 0:
			return "it is an access point"
		}
		return ""
	}
	return func(mac string) string {
		if len(d.Viewers) == 0 {
			return "no device used for this panel is known yet (open the panel once from your own device)"
		}
		if why := own(mac); why != "" {
			return why
		}
		if partner := pairs[mac]; partner != "" {
			if why := own(partner); why != "" {
				return "its Wi-Fi 7 pair " + partner + ": " + why
			}
		}
		return ""
	}
}

func qWas(p *QProfile, kind, v string) []string {
	var out []string
	for _, x := range p.Values[kind] {
		if qBanded(kind) && qContext(x) != qContext(v) {
			continue
		}
		out = append(out, x)
	}
	return out
}

type qDetectMsg struct {
	mac, label, level string
	signals           []QSignal
	moved             bool
	skipped           string
}

var qSignalText = map[string]string{
	qSigDHCP:     "DHCP fingerprint",
	qSigVendor:   "DHCP vendor class",
	qSigHostname: "hostname",
	qSigClientID: "DHCP client id",
	qSigIP:       "address it was not given",
	qSigPlaces:   "active on several networks at once",
	qSigRadio:    "Wi-Fi capabilities",
	qSigRoam:     "alternating between access points",
	qSigURadio:   "Wi-Fi on UniFi",
	qSigMedium:   "connection on UniFi",
}

func qSignalLine(s QSignal) string {
	name := qSignalText[s.Kind]
	if name == "" {
		name = s.Kind
	}
	switch {
	case len(s.Was) > 0:
		return fmt.Sprintf("%s: %s (known: %s)", name, s.Now, strings.Join(s.Was, " | "))
	default:
		return fmt.Sprintf("%s: %s", name, s.Now)
	}
}

func qNotifyDetect(msgs []qDetectMsg, mass int, channels func() bool, notify func(string, string, string, bool)) {
	if !channels() || len(msgs) == 0 {
		return
	}
	if mass > 0 {
		text := fmt.Sprintf("%d approved devices changed within minutes (DHCP, address or Wi-Fi details). That is usually a change on the router or a firmware update, not copied addresses: nothing is moved, and single messages pause until it settles. See the panel's Quarantine page.", mass)
		notify("NetGrip", "⚠️ <b>NetGrip</b>\n"+htmlEsc(text), "⚠️ NetGrip\n"+text, false)
		return
	}
	for _, m := range msgs {
		var lines []string
		for _, s := range m.signals {
			lines = append(lines, "• "+qSignalLine(s))
		}
		head, icon := fmt.Sprintf("%s changed", m.label), "ℹ️"
		tail := "If that was not you, check it on the panel's Quarantine page."
		if m.level == "alert" {
			head, icon = "Possible copied MAC: "+m.label, "⚠️"
			tail = "Check it on the panel's Quarantine page."
		}
		switch {
		case m.moved:
			tail = "It was moved back to quarantine. Approve it again on the panel's Quarantine page if it is yours."
		case m.skipped != "":
			tail = "It was not moved back to quarantine automatically: " + m.skipped + ". " + tail
		}
		plain := fmt.Sprintf("%s NetGrip\n%s\nMAC: %s\n%s\n%s", icon, head, m.mac, strings.Join(lines, "\n"), tail)
		html := fmt.Sprintf("%s <b>NetGrip</b>\n<b>%s</b>\nMAC: %s\n%s\n%s", icon, htmlEsc(head), m.mac, htmlEsc(strings.Join(lines, "\n")), htmlEsc(tail))
		notify("NetGrip", html, plain, m.level == "alert")
	}
}

// ---- Panel ----

func qDetectProbeLocked(st *qState, ident qIdent, now time.Time) QDetectProbe {
	d := st.Detect
	p := QDetectProbe{Enabled: d.Enabled, Auto: d.Auto, Suspects: []QSuspectRow{}, Sources: []string{}}
	if !d.Enabled {
		return p
	}
	for mac, pr := range d.Profiles {
		if _, ok := st.Approved[mac]; !ok {
			continue
		}
		p.Profiles++
		if until := pr.Since + int64(qDetectLearn/time.Second); until > now.Unix() {
			p.Learning++
			if until > p.LearnUntil {
				p.LearnUntil = until
			}
		}
	}
	for mac, s := range d.Suspects {
		if s.Dismissed != 0 {
			continue
		}
		dev := ident.device(mac)
		if a, ok := st.Approved[mac]; ok && a.Name != "" {
			dev.Name = a.Name
		}
		row := QSuspectRow{QDevice: dev, QSuspect: *s}
		if active := qActive(s.Signals); len(active) > 0 {
			row.Signals = active // evidence dismissed before is not shown again
		}
		p.Suspects = append(p.Suspects, row)
	}
	sort.Slice(p.Suspects, func(i, j int) bool {
		a, b := p.Suspects[i], p.Suspects[j]
		if (a.Level == "alert") != (b.Level == "alert") {
			return a.Level == "alert"
		}
		if a.Last != b.Last {
			return a.Last > b.Last
		}
		return a.MAC < b.MAC
	})
	qDetectSourcesMu.Lock()
	p.Sources = append(p.Sources, qDetectSources...)
	qDetectSourcesMu.Unlock()
	return p
}

var (
	qDetectSourcesMu sync.Mutex
	qDetectSources   []string
)

// QuarantineDetectSet turns the detection on or off and sets the automatic
// action. Turning it off forgets the profiles (a restart learns afresh).
func QuarantineDetectSet(enabled, auto bool) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	st := loadQState()
	if enabled && !st.Enabled {
		return probeQuarantineLocked(), fmt.Errorf("turn the quarantine on first")
	}
	if !enabled {
		st.Detect = QDetect{}
	} else {
		st.Detect.Enabled, st.Detect.Auto = true, auto
	}
	qForceFull = true // the first check runs at the next poll
	err := saveQState(st)
	return probeQuarantineLocked(), err
}

// QuarantineSuspectResolve: "same" adds the reported values to the device's
// profile; "dismiss" hides the report and keeps its evidence quiet (only a
// new signal opens it again).
func QuarantineSuspectResolve(mac, action string) (QuarantineProbe, error) {
	qMu.Lock()
	defer qMu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	st := loadQState()
	s := st.Detect.Suspects[mac]
	if s == nil {
		return probeQuarantineLocked(), fmt.Errorf("no report for this device")
	}
	switch action {
	case "same":
		if p := st.Detect.Profiles[mac]; p != nil {
			for _, sig := range s.Signals {
				qLearnValue(p, sig.Kind, sig.Now)
			}
		}
	case "dismiss":
		if s.Action == "" {
			s.Dismissed = time.Now().Unix()
			s.NotifiedSig = len(s.Signals)
			for i := range s.Signals {
				s.Signals[i].Dismissed = true
			}
			s.Level = qLevel(s.Signals)
			return probeQuarantineLocked(), saveQState(st)
		}
	default:
		return probeQuarantineLocked(), fmt.Errorf("unknown action %q", action)
	}
	delete(st.Detect.Suspects, mac)
	err := saveQState(st)
	return probeQuarantineLocked(), err
}
