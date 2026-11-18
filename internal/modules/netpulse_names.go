package modules

// Client names from NetPulse: display only. With each full push the
// embedded agent may get back the names the NetPulse server knows for
// devices (its own overrides, mDNS and Cast/AirPlay names, reverse DNS,
// the UniFi controller...), and only from an HTTPS server with a pinned
// key. The clients page shows one where NetGrip has no name at all: no
// lease host name, reservation, quarantine name or name set here, only
// the bare address.
//
// It is cosmetic and optional. The names are applied to a copy of the
// list the page and the new-client notification show (WithNetPulseNames),
// never to the list other features use (the quarantine, device names in
// DHCP, telemetry), and nothing is written anywhere. No NetPulse, an older
// one, a server that is down or sends nothing usable: the page shows what
// it showed before. A received set is used for a day at most.

import (
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	npNamesMax    = 4096
	npNameMaxLen  = 63
	npNamesMaxAge = 24 * time.Hour
)

type npNameSet struct {
	names map[string]string
	at    time.Time
}

var (
	npNames atomic.Pointer[npNameSet]
	npNow   = time.Now // tests
)

// NoteNetPulseNames takes the names from a push reply (the agent's
// callback). Everything in it came from another machine: only well-formed
// MACs, and printable names of a sensible length, are kept.
func NoteNetPulseNames(in map[string]string) {
	out := make(map[string]string, min(len(in), npNamesMax))
	for mac, name := range in {
		if len(out) >= npNamesMax {
			break
		}
		mac = strings.ToLower(strings.TrimSpace(mac))
		if !reMac.MatchString(mac) {
			continue
		}
		name = npCleanName(name)
		if name == "" || looksLikeMAC(name) {
			continue
		}
		out[mac] = name
	}
	npNames.Store(&npNameSet{names: out, at: npNow()})
}

// npCleanName drops control and text-direction characters, folds runs of
// spaces and bounds the length.
func npCleanName(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r): // tabs and line breaks too: one space
			space = true
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), r == 0x200B, r == 0xFEFF: // zero-width space, BOM
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) > npNameMaxLen {
		out = string([]rune(out)[:npNameMaxLen])
	}
	return strings.TrimSpace(out)
}

// netpulseNameFor: NetPulse's name for mac, or "" (none, or too old).
func netpulseNameFor(mac string) string {
	s := npNames.Load()
	if s == nil || npNow().Sub(s.at) > npNamesMaxAge {
		return ""
	}
	return s.names[strings.ToLower(mac)]
}

// WithNetPulseNames returns a copy of clients in which a client NetGrip
// has no name for (its name is its address, and nothing named it) shows
// NetPulse's, marked with NameSource "netpulse". The list passed in is not
// changed.
func WithNetPulseNames(clients []Client) []Client {
	out := make([]Client, len(clients))
	copy(out, clients)
	if npNames.Load() == nil {
		return out
	}
	for i := range out {
		c := &out[i]
		if c.NameSource != "" || (c.Name != "" && !strings.EqualFold(c.Name, c.MAC)) {
			continue
		}
		if n := netpulseNameFor(c.MAC); n != "" {
			c.Name, c.NameSource = n, "netpulse"
		}
	}
	return out
}
