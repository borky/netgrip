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
// each time they change it); the oldest go first.
const knownClientsMax = 4096

type knownClientsFile struct {
	FirstSeen map[string]int64 `json:"first_seen"`
}

func loadKnownClients() (map[string]int64, bool) {
	data, err := os.ReadFile(knownClientsPath)
	if err != nil {
		return nil, false
	}
	var f knownClientsFile
	if err := json.Unmarshal(data, &f); err != nil || f.FirstSeen == nil {
		return nil, false
	}
	out := make(map[string]int64, len(f.FirstSeen))
	for mac, at := range f.FirstSeen {
		if mac = strings.ToLower(mac); reMac.MatchString(mac) {
			out[mac] = at
		}
	}
	return out, true
}

func saveKnownClients(known map[string]int64) error {
	if len(known) > knownClientsMax {
		macs := make([]string, 0, len(known))
		for mac := range known {
			macs = append(macs, mac)
		}
		sort.Slice(macs, func(i, j int) bool {
			if known[macs[i]] != known[macs[j]] {
				return known[macs[i]] < known[macs[j]]
			}
			return macs[i] < macs[j]
		})
		for _, mac := range macs[:len(known)-knownClientsMax] {
			delete(known, mac)
		}
	}
	data, err := json.Marshal(knownClientsFile{FirstSeen: known})
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

// newClients returns the clients never seen before and records them. The
// first call with no saved list records everything known and reports
// nothing.
func (m *Monitor) newClients(clients []Client, now time.Time) []Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := now.Unix()
	if !m.knownLoaded {
		known, ok := loadKnownClients()
		m.known, m.knownLoaded = known, true
		if !ok {
			m.known = map[string]int64{}
			for _, c := range clients {
				if mac := strings.ToLower(c.MAC); reMac.MatchString(mac) {
					m.known[mac] = at
				}
			}
			for _, mac := range knownSeedMACsFn() {
				if mac = strings.ToLower(mac); reMac.MatchString(mac) {
					m.known[mac] = at
				}
			}
			if err := knownClientsSave(m.known); err != nil {
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
		if _, ok := m.known[mac]; ok {
			continue
		}
		m.known[mac] = at
		fresh = append(fresh, c)
	}
	if len(fresh) > 0 {
		if err := knownClientsSave(m.known); err != nil {
			log.Printf("netgrip: known clients: %v", err)
		}
	}
	return fresh
}
