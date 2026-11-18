package modules

// Known clients: which devices the "new client" notification has already
// seen. It used to remember only the previous check (15 s earlier), so any
// device that dropped out of the client list for a moment came back as
// "new": a wired access point quiet towards the router for five minutes, a
// phone whose Wi-Fi slept. Now a device is new once: the first time it is
// ever seen. The list is kept on flash, written only when a new device
// shows up.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	knownClientsPath = "/etc/netgrip/known-clients.json"
	// Seams for tests (the client list itself: listClientsFn).
	knownSeedMACsFn  = knownSeedMACs
	knownClientsSave = saveKnownClients
)

// knownClientsMax bounds the list (devices with random addresses add one
// each time they change it). The ones not seen for longest go first, never
// one in the list right now: dropping a device that is online would
// announce it again at the next check.
const knownClientsMax = 4096

type knownClientsFile struct {
	FirstSeen map[string]int64 `json:"first_seen"`
	LastSeen  map[string]int64 `json:"last_seen,omitempty"`
}

func loadKnownClients() (first, last map[string]int64, ok bool) {
	data, err := os.ReadFile(knownClientsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("netgrip: known clients: %v; starting it again", err)
		}
		return nil, nil, false
	}
	var f knownClientsFile
	if err := json.Unmarshal(data, &f); err != nil || f.FirstSeen == nil {
		log.Printf("netgrip: known clients: %s cannot be read; starting it again", knownClientsPath)
		return nil, nil, false
	}
	first = make(map[string]int64, len(f.FirstSeen))
	last = make(map[string]int64, len(f.FirstSeen))
	for mac, at := range f.FirstSeen {
		if mac = strings.ToLower(mac); reMac.MatchString(mac) {
			first[mac] = at
			last[mac] = at
		}
	}
	for mac, at := range f.LastSeen {
		if mac = strings.ToLower(mac); reMac.MatchString(mac) {
			if _, ok := first[mac]; ok {
				last[mac] = at
			}
		}
	}
	return first, last, true
}

// saveKnownClients writes the list, first trimming it to knownClientsMax
// (see there); present: the MACs in the client list now.
func saveKnownClients(known, lastSeen map[string]int64, present map[string]bool) error {
	if len(known) > knownClientsMax {
		macs := make([]string, 0, len(known))
		for mac := range known {
			if !present[mac] {
				macs = append(macs, mac)
			}
		}
		seen := func(mac string) int64 {
			if at, ok := lastSeen[mac]; ok {
				return at
			}
			return known[mac]
		}
		sort.Slice(macs, func(i, j int) bool {
			if seen(macs[i]) != seen(macs[j]) {
				return seen(macs[i]) < seen(macs[j])
			}
			return macs[i] < macs[j]
		})
		drop := len(known) - knownClientsMax
		if drop > len(macs) {
			drop = len(macs)
		}
		for _, mac := range macs[:drop] {
			delete(known, mac)
			delete(lastSeen, mac)
		}
	}
	last := make(map[string]int64, len(known))
	for mac := range known {
		if at, ok := lastSeen[mac]; ok {
			last[mac] = at
		}
	}
	data, err := json.Marshal(knownClientsFile{FirstSeen: known, LastSeen: last})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(knownClientsPath), 0o750); err != nil {
		return err
	}
	return writeFileDurable(knownClientsPath, data)
}

// knownSeedMACs: devices the router already knows of besides the ones in
// the list right now (some are quiet at that moment), so turning this on
// does not announce them all once: DHCP leases, reservations and the ARP
// table.
func knownSeedMACs() []string {
	var out []string
	if leases, _, err := leasesForClients(); err == nil {
		for _, l := range leases {
			out = append(out, l.MAC)
		}
	}
	for mac := range dhcpReservations() {
		out = append(out, mac)
	}
	for mac := range localArp() {
		out = append(out, mac)
	}
	return out
}

// newClients returns the clients never seen before and records them.
// silent records without reporting (see Monitor.resync); the first call
// with no saved list records everything known and reports nothing.
func (m *Monitor) newClients(clients []Client, now time.Time, silent bool) []Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := now.Unix()
	present := map[string]bool{}
	for _, c := range clients {
		if mac := strings.ToLower(c.MAC); reMac.MatchString(mac) {
			present[mac] = true
		}
	}
	if !m.knownLoaded {
		known, last, ok := loadKnownClients()
		m.known, m.lastSeen, m.knownLoaded = known, last, true
		if !ok {
			m.known, m.lastSeen = map[string]int64{}, map[string]int64{}
			for mac := range present {
				m.known[mac] = at
			}
			for _, mac := range knownSeedMACsFn() {
				if mac = strings.ToLower(mac); reMac.MatchString(mac) {
					m.known[mac] = at
				}
			}
			for mac := range present {
				m.lastSeen[mac] = at
			}
			if err := knownClientsSave(m.known, m.lastSeen, present); err != nil {
				log.Printf("netgrip: known clients: %v", err)
			}
			return nil
		}
	}
	var fresh []Client
	for _, c := range clients {
		mac := strings.ToLower(c.MAC)
		if !reMac.MatchString(mac) {
			continue
		}
		m.lastSeen[mac] = at
		if _, ok := m.known[mac]; ok {
			continue
		}
		m.known[mac] = at
		fresh = append(fresh, c)
	}
	if len(fresh) > 0 {
		if err := knownClientsSave(m.known, m.lastSeen, present); err != nil {
			log.Printf("netgrip: known clients: %v", err)
		}
	}
	if silent {
		return nil
	}
	return fresh
}
