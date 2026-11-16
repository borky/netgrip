package modules

// Device names in DHCP. A name the user types for a device - approving it in
// the quarantine, or naming it on the clients page - is also written as a
// DHCP host entry (MAC and name, no fixed address) when the device does not
// name itself. dnsmasq then hands that name out and answers for it in local
// DNS, and everything reading the router's DHCP config or leases (the clients
// page, NetPulse's agent) shows it.
//
// When it runs: when the user names a device, for that device; once at each
// start, for names given before (and not written yet); and, for a device
// named before it had a lease (refused at the access point, or off), when
// its first lease appears: the worker looks for it once a minute only while
// such a device is waiting. NetGrip remembers which name it wrote for each
// device (devNamesRecordPath) and writes again only when the user gives a
// different one, or names the device again, so an entry deleted by hand
// stays deleted and nothing is rewritten on every start.
//
// What it touches: only NetGrip's own entries - netgrip_devname_<mac>, and
// the clients page's reservation netgrip_host_<mac> - never an entry the
// user made, and never a name the user set on NetGrip's reservation by hand
// (one NetGrip wrote carries netgrip_named='1'). A device that names itself,
// a name another device or a local DNS record already has, and a name
// dnsmasq would read as something else (a lease time, "ignore") are left
// alone.
//
// DHCP is shared by every network: each change runs under the quarantine's
// lock (the quarantine changes DHCP too, and both restore the whole package
// when their check fails), and is checked against what dnsmasq served before;
// the DHCP config is restored if a network lost it or dnsmasq stopped.

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
)

const (
	devNamePfx = "netgrip_devname_"
	// NetGrip's own reservations (clients page), see SetClientReservation.
	devReservePfx = "netgrip_host_"
	// devNamedOpt marks a name NetGrip wrote into one of its own entries.
	devNamedOpt  = "netgrip_named"
	devNameMax   = 63
	devWaitEvery = time.Minute
)

var (
	// devNamesQueue: the MACs named since the last pass; devNamesKickCh
	// wakes the worker. devNamesDeferred: named, no lease yet (worker only).
	devNamesQueueMu  sync.Mutex
	devNamesQueue    = map[string]bool{}
	devNamesKickCh   = make(chan struct{}, 1)
	devNamesOnce     sync.Once
	devNamesDeferred = map[string]bool{}
	// devNamesRecordPath: the name NetGrip last wrote for each MAC.
	devNamesRecordPath = "/etc/netgrip/devnames.json"
	devNamesRecordMu   sync.Mutex
	// Seams for tests.
	devNamesLocalFn = func() bool { return executor.ServiceRunning("dnsmasq") }
	devNamesApplyFn = qApplyClean
	// devNamesOptionLike: a dhcp-host field dnsmasq reads as a lease time.
	devNamesOptionLike = regexp.MustCompile(`^[0-9]+[smhdwSMHDW]?$`)
)

// StartDeviceNames starts the worker. It makes one pass a minute after the
// start, then waits for names (kickDeviceNames) and, while a named device
// has no lease, looks for its lease once a minute.
func StartDeviceNames() {
	devNamesOnce.Do(func() {
		go func() {
			time.Sleep(time.Minute) // let leases and dnsmasq settle after a start
			devNamesDeferred = devNamesPass(nil)
			for {
				var wait <-chan time.Time
				if len(devNamesDeferred) > 0 {
					wait = time.After(devWaitEvery)
				}
				select {
				case <-devNamesKickCh:
					time.Sleep(2 * time.Second) // a burst of names in one pass
					devNamesQueueMu.Lock()
					only := devNamesQueue
					devNamesQueue = map[string]bool{}
					devNamesQueueMu.Unlock()
					for m := range only {
						delete(devNamesDeferred, m)
					}
					for m := range devNamesPass(only) {
						devNamesDeferred[m] = true
					}
				case <-wait:
					if seen := devNamesLeased(devNamesDeferred); len(seen) > 0 {
						for m := range seen {
							delete(devNamesDeferred, m)
						}
						for m := range devNamesPass(seen) {
							devNamesDeferred[m] = true
						}
					}
				}
			}
		}()
	})
}

// kickDeviceNames asks for a pass for these devices. Never blocks.
func kickDeviceNames(macs ...string) {
	devNamesQueueMu.Lock()
	for _, m := range macs {
		if m = strings.ToLower(strings.TrimSpace(m)); m != "" {
			devNamesQueue[m] = true
		}
	}
	devNamesQueueMu.Unlock()
	select {
	case devNamesKickCh <- struct{}{}:
	default:
	}
}

// devNamesLeased: those of macs the router has a lease for now.
func devNamesLeased(macs map[string]bool) map[string]bool {
	leases, source, _ := leasesForClients()
	out := map[string]bool{}
	if source != "local" {
		return out
	}
	for _, l := range leases {
		if m := strings.ToLower(l.MAC); macs[m] {
			out[m] = true
		}
	}
	return out
}

// devHostname turns a name into a DHCP/DNS host name: letters, digits and
// hyphens, a run of anything else becoming one hyphen, no hyphen at either
// end, at most devNameMax characters. "" when nothing usable is left, or
// when dnsmasq would read it as something other than a name: a lease time
// ("2024", "12h"), "infinite" or "ignore" (which takes the device off DHCP).
func devHostname(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > devNameMax {
		s = strings.TrimRight(s[:devNameMax], "-")
	}
	if l := strings.ToLower(s); l == "ignore" || l == "infinite" || devNamesOptionLike.MatchString(s) {
		return ""
	}
	return s
}

// devNamesWanted: the names the user typed, by MAC: one set on the clients
// page, else the one typed when approving it. Labels the quarantine's set-up
// filled in (a chip maker's name, say) are not, also when they come back as
// a clients-page name because the edit dialog was saved with them.
func devNamesWanted() map[string]string {
	out := map[string]string{}
	r := qReportCurrent()
	for mac, n := range r.names {
		if r.typed[mac] {
			out[mac] = n
		}
	}
	for mac, m := range clientMeta() {
		mac = strings.ToLower(mac)
		if m.Name == "" || looksLikeMAC(m.Name) {
			continue
		}
		if label, ok := r.names[mac]; ok && !r.typed[mac] && strings.EqualFold(strings.TrimSpace(label), strings.TrimSpace(m.Name)) {
			continue
		}
		out[mac] = m.Name
	}
	return out
}

// devNamesPlan computes the DHCP changes. dhcp: the parsed DHCP config;
// leases: each MAC's lease hostname ("*" or "" when it sends none; absent
// when there is no lease); want: host names (devHostname) by MAC. It returns
// the ops (no commit), what they name, why the others were left alone, and
// those waiting for a lease. Pure.
func devNamesPlan(dhcp map[string]uciSection, leases map[string]string, want map[string]string) (ops []executor.Op, named, skipped map[string]string, noLease map[string]bool) {
	named, skipped, noLease = map[string]string{}, map[string]string{}, map[string]bool{}
	byMAC := map[string][]string{}
	taken := map[string]string{} // lowercase name -> its MAC ("" when it has none)
	names := make([]string, 0, len(dhcp))
	for s := range dhcp {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		sec := dhcp[s]
		switch sec.Type {
		case "host":
			var macs []string
			for _, v := range sec.Options["mac"] {
				for _, m := range strings.Fields(v) {
					macs = append(macs, strings.ToLower(m))
				}
			}
			for _, m := range macs {
				byMAC[m] = append(byMAC[m], s)
			}
			if n := strings.ToLower(sec.Option("name")); n != "" {
				owner := ""
				if len(macs) > 0 {
					owner = macs[0]
				}
				taken[n] = owner
			}
		case "domain":
			if n := strings.ToLower(sec.Option("name")); n != "" {
				taken[n] = ""
			}
		}
	}
	for mac, h := range leases {
		if h != "" && h != "*" {
			if _, ok := taken[strings.ToLower(h)]; !ok {
				taken[strings.ToLower(h)] = mac
			}
		}
	}

	macs := make([]string, 0, len(want))
	for m := range want {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		host := want[mac]
		if host == "" {
			skipped[mac] = "the name cannot be a DHCP host name (no letters, or read as a lease time or option)"
			continue
		}
		if other, ok := taken[strings.ToLower(host)]; ok && other != mac {
			skipped[mac] = "another device or local DNS record already uses the name " + host
			continue
		}
		hex := strings.ReplaceAll(mac, ":", "")
		own, reserve := devNamePfx+hex, devReservePfx+hex
		lease, hasLease := leases[mac]
		selfNamed := hasLease && lease != "" && lease != "*"
		secs := byMAC[mac]
		var target string
		switch {
		case len(secs) == 0:
			if _, edited := dhcp[own]; edited {
				skipped[mac] = "its NetGrip DHCP entry was changed by hand"
				continue
			}
			if !hasLease {
				skipped[mac], noLease[mac] = "no lease yet: named when it first gets one", true
				continue
			}
			if selfNamed {
				skipped[mac] = "it names itself (" + lease + ")"
				continue
			}
			target = own
		case len(secs) == 1 && (secs[0] == own || secs[0] == reserve):
			sec := dhcp[secs[0]]
			cur := sec.Option("name")
			ours := sec.Option(devNamedOpt) == "1"
			switch {
			case cur == host:
				continue // already so
			case cur != "" && !ours:
				skipped[mac] = "its DHCP entry has a name set by hand (" + cur + ")"
				continue
			case cur == "" && !hasLease:
				skipped[mac], noLease[mac] = "no lease yet: named when it first gets one", true
				continue
			case cur == "" && selfNamed:
				skipped[mac] = "it names itself (" + lease + ")"
				continue
			}
			target = secs[0]
		default:
			skipped[mac] = "it has a DHCP entry of its own"
			continue
		}
		opts := map[string][]string{"name": {host}, devNamedOpt: {"1"}}
		if _, exists := dhcp[target]; !exists {
			opts["mac"] = []string{mac}
		}
		ensureSection(&ops, dhcp, "dhcp", target, "host", opts)
		named[mac] = host
		taken[strings.ToLower(host)] = mac
	}
	return ops, named, skipped, noLease
}

func devNamesRecord() map[string]string {
	out := map[string]string{}
	if b, err := os.ReadFile(devNamesRecordPath); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func devNamesRecordAdd(named map[string]string) {
	devNamesRecordMu.Lock()
	defer devNamesRecordMu.Unlock()
	rec := devNamesRecord()
	for m, h := range named {
		rec[m] = h
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err == nil {
		err = writeFileDurable(devNamesRecordPath, b)
	}
	if err != nil {
		log.Printf("netgrip: device names: recording what was written: %v", err)
	}
}

// devNamesPass writes the names not written yet of the devices in only (of
// every named device when only is nil). It returns those waiting for a
// lease.
func devNamesPass(only map[string]bool) map[string]bool {
	if !devNamesLocalFn() {
		return nil // DHCP is served elsewhere (an access point)
	}
	all := devNamesWanted()
	rec := devNamesRecord()
	want := map[string]string{}
	for _, mac := range sortedKeys(only) {
		if _, ok := all[mac]; !ok {
			log.Printf("netgrip: device names: %s has no name typed for it (a label from the quarantine's set-up is not written to DHCP)", mac)
		}
	}
	for mac, n := range all {
		if only != nil && !only[mac] {
			continue
		}
		host := devHostname(n)
		if only == nil && host != "" && rec[mac] == host {
			// The start's pass: written before, so an entry deleted since
			// stays deleted. Naming a device again looks at the config
			// itself (a rollback or a restored backup may have taken the
			// entry away), and the plan skips a name already in place.
			continue
		}
		want[mac] = host
	}
	if len(want) == 0 {
		return nil
	}
	leaseList, source, _ := leasesForClients()
	if source != "local" {
		return nil
	}
	leases := map[string]string{}
	for _, l := range leaseList {
		leases[strings.ToLower(l.MAC)] = l.Hostname
	}

	qMu.Lock()
	defer qMu.Unlock()
	show, err := uciShowFn("dhcp")
	if err != nil {
		return nil
	}
	ops, named, skipped, noLease := devNamesPlan(parseUCIShow(show, "dhcp"), leases, want)
	if only != nil { // said for what the user just named, not for the start's pass
		for _, mac := range sortedKeys(skipped) {
			log.Printf("netgrip: device names: %s not written to DHCP: %s", mac, skipped[mac])
		}
	}
	if len(ops) == 0 {
		return noLease
	}
	if err := QuarantinePendingCheck([]string{"dhcp"}); err != nil {
		log.Printf("netgrip: device names: not writing DHCP names now: %v", err)
		return noLease
	}
	before := qDnsmasqRuntimeFn()
	snap, err := qSnapshotFn("dhcp")
	if err != nil {
		log.Printf("netgrip: device names: cannot take a snapshot of the DHCP config, nothing changed: %v", err)
		return noLease
	}
	started := time.Now()
	ops = append(ops,
		executor.Op{Kind: "uci_commit", Args: []string{"dhcp"}},
		executor.Op{Kind: "initd", Args: []string{"dnsmasq", "reload"}})
	why := ""
	if err := devNamesApplyFn(ops); err != nil {
		why = err.Error()
	} else {
		qDnsmasqWaitFn(started)
		why = devNamesCheck(before)
		if why != "" {
			time.Sleep(qDHCPRecheckDelay) // a network briefly down after a reload
			why = devNamesCheck(before)
		}
	}
	if why != "" {
		log.Printf("netgrip: device names: DHCP check failed (%s); restoring the DHCP config", why)
		if err := qRestoreFn("dhcp", snap); err != nil {
			log.Printf("netgrip: device names: restoring the DHCP config: %v", err)
		}
		if err := devNamesApplyFn([]executor.Op{{Kind: "initd", Args: []string{"dnsmasq", "reload"}}}); err != nil {
			log.Printf("netgrip: device names: reloading dnsmasq: %v", err)
		}
		return noLease
	}
	devNamesRecordAdd(named)
	invalidateClients()
	for _, m := range sortedKeys(named) {
		log.Printf("netgrip: device names: %s is now %q in DHCP and local DNS", m, named[m])
	}
	return noLease
}

// devNamesCheck: "" when dnsmasq runs and serves every network it served
// before.
func devNamesCheck(before qDnsmasqServing) string {
	if !devNamesLocalFn() {
		return "dnsmasq is not running after the reload"
	}
	return qDHCPRegression(before, qDnsmasqRuntimeFn(), qOwnDHCP{})
}
