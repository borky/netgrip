package modules

// The quarantine and NetPulse (phase 6). Each full push to the monitoring
// server carries every device's quarantine state, which its device list
// shows; the server answers with what its UniFi controller says about the
// Wi-Fi those devices use, which the copied-MAC detection compares. The
// embedded agent does both only with an HTTPS server whose key is pinned:
// the trusted list is what someone copying a MAC wants, and a forged answer
// must not raise alerts. That answer never counts towards the automatic
// move (see qOwnSignals). The router stays the source of truth: nothing
// here is needed for the quarantine to work.

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// qStationsMaxAge: an answer older than this says nothing about now (full
// pushes come every 30 s by default; the server's controller read is at
// most five minutes old on top).
const qStationsMaxAge = 5 * time.Minute

// qMaxStations bounds what one answer may hold.
const qMaxStations = 4096

// qUnifiObs is one device as UniFi sees it, as signal values. Only Wi-Fi
// clients of UniFi access points: UniFi calls "wired" any address it learns
// on a switch port, which includes clients of other access points and of
// the router's own Wi-Fi, so wired versus Wi-Fi is not compared.
type qUnifiObs struct {
	radio string // "<ap model>/<band>:<standard>[,mlo]"
}

var (
	qStationsMu sync.Mutex
	qStations   map[string]qUnifiObs
	qStationsAt time.Time
	// qStationsNow: the clock (tests).
	qStationsNow = time.Now
)

// QuarantineNoteStations takes the server's answer (the agent's callback).
// It only records it: the next full check compares it.
func QuarantineNoteStations(list []probe.QuarantineStation) {
	out := make(map[string]qUnifiObs, len(list))
	for i, s := range list {
		if i >= qMaxStations {
			break
		}
		mac := strings.ToLower(strings.TrimSpace(s.MAC))
		if !reMac.MatchString(mac) {
			continue
		}
		if o, ok := qStationObs(s); ok {
			out[mac] = o
		}
	}
	qStationsMu.Lock()
	qStations, qStationsAt = out, qStationsNow()
	qStationsMu.Unlock()
}

// qStationsSnapshot: the last answer, if recent.
func qStationsSnapshot(now time.Time) (map[string]qUnifiObs, bool) {
	qStationsMu.Lock()
	defer qStationsMu.Unlock()
	if qStations == nil || now.Sub(qStationsAt) > qStationsMaxAge || now.Before(qStationsAt.Add(-time.Minute)) {
		return nil, false
	}
	return qStations, true
}

// qStationObs turns one station into signal values (ok false: nothing to
// compare). Everything in it came from another machine: only plain codes
// are kept. The context (before ':') is what the connection depends on, not
// the device: the access point model and the band (an older model offers
// an older standard). The value is what the device chose there: the Wi-Fi
// standard and Wi-Fi 7 multi-link, so a device that copies a Wi-Fi 7
// phone's address but cannot do the same shows. Spatial streams are left
// out: the controller may report those in use, which vary.
func qStationObs(s probe.QuarantineStation) (qUnifiObs, bool) {
	if s.Wired {
		return qUnifiObs{}, false
	}
	proto := qPlainCode(s.Proto, 4, false)
	if proto == "" {
		return qUnifiObs{}, false
	}
	band := ""
	switch s.Band {
	case "2g", "5g", "6g":
		band = s.Band
	}
	v := qPlainCode(s.APModel, 24, true) + "/" + band + ":" + proto
	if s.MLO {
		v += ",mlo"
	}
	return qUnifiObs{radio: v}, true
}

// qPlainCode keeps a short code: lowercase letters only, or, for a model,
// letters, digits, '-', '_' and '.'.
func qPlainCode(s string, max int, model bool) string {
	if !model {
		s = strings.ToLower(s)
	}
	var b strings.Builder
	for _, c := range s {
		ok := c >= 'a' && c <= 'z'
		if model {
			ok = ok || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		}
		if !ok {
			if model {
				continue
			}
			return ""
		}
		if b.Len() >= max {
			if !model {
				return ""
			}
			break
		}
		b.WriteRune(c)
	}
	return b.String()
}

// quarantineReportInfo is the state the agent sends with each full push.
// It reads the saved state's copy in memory, never waiting for the
// quarantine's lock. nil when the quarantine was never set up.
func quarantineReportInfo() *probe.QuarantineInfo {
	st := loadQState()
	if !st.Enabled {
		if len(st.Approved) == 0 && len(st.Pending) == 0 {
			return nil // never used: nothing to report, nothing to clear
		}
		return &probe.QuarantineInfo{Enabled: false}
	}
	info := &probe.QuarantineInfo{Enabled: true, Devices: make([]probe.QuarantineDevice, 0, len(st.Approved)+len(st.Pending))}
	if st.Pause.active(time.Now()) {
		info.PauseUntil, info.PauseKind = st.Pause.Until, st.Pause.Kind
	}
	report := map[string]string{}
	if st.Detect.Enabled {
		for mac, s := range st.Detect.Suspects {
			switch {
			case s.Action != "" && s.Dismissed == 0:
				// Moved back automatically: the most important state. It
				// waits even before it asks to join again.
				report[mac] = "alert"
				if _, ok := st.Approved[mac]; !ok {
					if _, ok := st.Pending[mac]; !ok {
						info.Devices = append(info.Devices, probe.QuarantineDevice{MAC: mac, State: "waiting", Report: "alert"})
					}
				}
			case s.Dismissed == 0 && len(qActive(s.Signals)) > 0:
				report[mac] = s.Level
			}
		}
	}
	for mac := range st.Approved {
		info.Devices = append(info.Devices, probe.QuarantineDevice{MAC: mac, State: "approved", Report: report[mac]})
	}
	for mac := range st.Pending {
		if _, ok := st.Approved[mac]; ok {
			continue
		}
		info.Devices = append(info.Devices, probe.QuarantineDevice{MAC: mac, State: "waiting", Report: report[mac]})
	}
	sort.Slice(info.Devices, func(i, j int) bool { return info.Devices[i].MAC < info.Devices[j].MAC })
	return info
}
