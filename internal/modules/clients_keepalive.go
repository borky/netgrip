package modules

// Wired client keepalive. A wired client is listed while the LAN bridge has
// its MAC in the forwarding table, and the bridge forgets a MAC after its
// ageing time (300 s by default) without a frame from it. A device that
// talks only to others behind the same switch (an access point and its
// controller, say) goes quiet towards the router for minutes, dropped out
// of the list and came back as a "new client". The ARP table cannot stand
// in: a router with fewer neighbours than gc_thresh1 (128) never clears a
// stale entry, so it would keep listing devices that left long ago.
//
// So, once a minute, each wired MAC that has been quiet for most of the
// ageing time gets one UDP datagram to the discard port of the address
// the ARP table gives it. The kernel confirms the neighbour (a unicast ARP
// request), and the device's answer, or any reply, refreshes the bridge
// entry. A device that left answers nothing and ages out as before, so the
// list still says only what the bridge saw. Nothing is sent on an access
// point (its list is its Wi-Fi stations) or to Wi-Fi ports.

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	keepaliveEvery = time.Minute
	// keepaliveMargin: a MAC this close to its ageing time is probed. More
	// than keepaliveEvery, so every quiet device gets one probe in time.
	keepaliveMargin = 90 * time.Second
	keepaliveMinGap = 50 * time.Second // per MAC
)

// fdbAge is one learned MAC on a bridge port and how long since its last
// frame.
type fdbAge struct {
	port string
	age  time.Duration
}

// Seams for tests.
var (
	fdbAgesFn       = fdbAges
	bridgeAgeingFn  = bridgeAgeing
	keepaliveArpFn  = bridgeArp
	keepaliveSendFn = keepaliveSend
)

var (
	keepaliveOnce sync.Once
	keepaliveMu   sync.Mutex
	keepaliveLast = map[string]time.Time{}
)

// StartWiredKeepalive starts the once-a-minute keepalive (see above).
func StartWiredKeepalive() {
	keepaliveOnce.Do(func() {
		go func() {
			for {
				time.Sleep(keepaliveEvery)
				wiredKeepaliveTick(time.Now())
			}
		}()
	})
}

// wiredKeepaliveTick probes the wired MACs about to be forgotten. It
// returns the addresses it probed (for tests).
func wiredKeepaliveTick(now time.Time) []string {
	if probeModeFn().Mode == "ap" {
		return nil
	}
	bridge := LANBridge()
	ages := fdbAgesFn(bridge)
	if len(ages) == 0 {
		return nil
	}
	ageing := bridgeAgeingFn(bridge)
	if ageing <= 0 {
		return nil
	}
	threshold := ageing - keepaliveMargin
	if threshold < ageing/2 {
		threshold = ageing / 2
	}
	arp := keepaliveArpFn(bridge)
	keepaliveMu.Lock()
	defer keepaliveMu.Unlock()
	var sent []string
	for mac, e := range ages {
		if e.age < threshold || isWirelessPortFn(e.port) {
			continue
		}
		ip := arp[mac]
		if ip == "" {
			continue
		}
		if t, ok := keepaliveLast[mac]; ok && now.Sub(t) < keepaliveMinGap {
			continue
		}
		keepaliveLast[mac] = now
		keepaliveSendFn(ip)
		sent = append(sent, ip)
	}
	// Forget MACs the bridge no longer has: the map stays as small as the
	// bridge table.
	for mac := range keepaliveLast {
		if _, ok := ages[mac]; !ok {
			delete(keepaliveLast, mac)
		}
	}
	return sent
}

// keepaliveSend sends one byte to the discard port (9): enough for the
// kernel to confirm the neighbour; no answer is needed or read.
func keepaliveSend(ip string) {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "9"), time.Second)
	if err != nil {
		return
	}
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
}

// fdbAges reads the bridge's forwarding table with each entry's age
// (brctl showmacs: port no, mac, is local, ageing timer in seconds), the
// youngest per MAC. Local entries (the router's own ports) are left out.
func fdbAges(bridge string) map[string]fdbAge {
	brifDir := "/sys/class/net/" + bridge + "/brif"
	entries, err := os.ReadDir(brifDir)
	if err != nil {
		return nil
	}
	portNames := map[int]string{}
	for _, e := range entries {
		data, err := os.ReadFile(brifDir + "/" + e.Name() + "/port_id")
		if err != nil {
			continue
		}
		id, err := strconv.ParseInt(strings.TrimSpace(string(data)), 0, 64)
		if err != nil {
			continue
		}
		portNames[int(id&0xff)] = e.Name()
	}
	out, err := exec.Command("brctl", "showmacs", bridge).Output()
	if err != nil {
		return nil
	}
	return parseFdbAges(string(out), portNames)
}

func parseFdbAges(out string, portNames map[int]string) map[string]fdbAge {
	ages := map[string]fdbAge{}
	lines := strings.Split(out, "\n")
	if len(lines) > 0 {
		lines = lines[1:] // header
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] == "yes" {
			continue
		}
		portNo, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		port, ok := portNames[portNo]
		if !ok {
			continue
		}
		mac := strings.ToLower(f[1])
		if !reMac.MatchString(mac) {
			continue
		}
		secs, err := strconv.ParseFloat(f[3], 64)
		if err != nil {
			continue
		}
		age := time.Duration(secs * float64(time.Second))
		if cur, ok := ages[mac]; !ok || age < cur.age {
			ages[mac] = fdbAge{port: port, age: age}
		}
	}
	return ages
}

// bridgeAgeing is how long the bridge keeps a quiet MAC (sysfs, in
// hundredths of a second).
func bridgeAgeing(bridge string) time.Duration {
	data, err := os.ReadFile("/sys/class/net/" + bridge + "/bridge/ageing_time")
	if err != nil {
		return 0
	}
	cs, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || cs <= 0 {
		return 0
	}
	return time.Duration(cs) * 10 * time.Millisecond
}

// bridgeArp is the ARP table's MAC -> address for the bridge and its VLAN
// devices only (bridge, bridge.<vid>): the networks the bridge's MACs live
// on, never an uplink.
func bridgeArp(bridge string) map[string]string {
	raw, err := os.ReadFile(arpFilePath)
	if err != nil {
		return map[string]string{}
	}
	return parseBridgeArp(string(raw), bridge)
}

func parseBridgeArp(content, bridge string) map[string]string {
	out := map[string]string{}
	for i, line := range strings.Split(content, "\n") {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		ip, flags, mac, dev := f[0], f[2], strings.ToLower(f[3]), f[5]
		if flags == "0x0" || !reMac.MatchString(mac) || mac == "00:00:00:00:00:00" {
			continue
		}
		if dev != bridge && !strings.HasPrefix(dev, bridge+".") {
			continue
		}
		out[mac] = ip
	}
	return out
}
