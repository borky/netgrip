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
// ageing time gets one UDP datagram to the discard port of each address
// the ARP table gives it on the bridge (a renumbered device may still have
// its old row). The kernel confirms the neighbour (a unicast ARP request),
// and the device's answer, or any reply, refreshes the bridge entry. A
// device that left answers nothing and ages out as before, so the list
// still says only what the bridge saw. Only addresses inside a subnet of
// the very device the row was learned on are probed (never one that would
// be routed elsewhere, out of an uplink). Nothing is sent on an access
// point (its list is its Wi-Fi stations) or to Wi-Fi ports.

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
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

// arpRow is one ARP entry: an address and the device it was learned on.
type arpRow struct {
	ip  string
	dev string
}

// Seams for tests.
var (
	fdbAgesFn       = fdbAges
	bridgeAgeingFn  = bridgeAgeing
	keepaliveArpFn  = bridgeArp
	keepaliveSendFn = keepaliveSend
	// The router's mode and LAN bridge, from the panel's caches: the tick
	// runs every minute for good, and probing them forks several commands.
	keepaliveModeFn = func() string {
		p, _ := CachedRead("mode", 10*time.Minute, func() (*ModeProbe, error) { return probeModeFn(), nil })
		if p == nil {
			return ""
		}
		return p.Mode
	}
	keepaliveBridgeFn = func() string {
		b, _ := CachedRead("keepalive|bridge", 10*time.Minute, func() (string, error) { return LANBridge(), nil })
		return b
	}
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
//
// Most ticks cost two small file reads (sysfs): the router's mode, the
// ARP table and its subnets are looked at only when some wired MAC is
// actually close to its ageing time.
func wiredKeepaliveTick(now time.Time) []string {
	bridge := keepaliveBridgeFn()
	if bridge == "" {
		return nil
	}
	// An ageing time this short (a non-default setting) leaves no room to
	// probe once a minute before entries go: nothing is done then.
	ageing := bridgeAgeingFn(bridge)
	if ageing < 2*keepaliveEvery {
		return nil
	}
	ages := fdbAgesFn(bridge)
	threshold := ageing - keepaliveMargin
	var due []string
	for mac, e := range ages {
		if e.age >= threshold && !isWirelessPortFn(e.port) {
			due = append(due, mac)
		}
	}
	keepaliveMu.Lock()
	defer keepaliveMu.Unlock()
	// Forget MACs the bridge no longer has: the map stays as small as the
	// bridge table.
	for mac := range keepaliveLast {
		if _, ok := ages[mac]; !ok {
			delete(keepaliveLast, mac)
		}
	}
	if len(due) == 0 || keepaliveModeFn() == "ap" {
		return nil
	}
	arp := keepaliveArpFn(bridge)
	subnets := clientSubnetsFn()
	var sent []string
	for _, mac := range due {
		var ips []string
		for _, r := range arp[mac] {
			if onDeviceSubnet(r.ip, r.dev, subnets) {
				ips = append(ips, r.ip)
			}
		}
		if len(ips) == 0 {
			continue
		}
		if t, ok := keepaliveLast[mac]; ok && now.Sub(t) < keepaliveMinGap {
			continue
		}
		keepaliveLast[mac] = now
		for _, ip := range ips {
			keepaliveSendFn(ip)
			sent = append(sent, ip)
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

// fdbAges reads the bridge's forwarding table with each entry's age, the
// youngest per MAC, from sysfs (brforward: the kernel's own records, no
// command to run and no tool needed). Local entries (the router's own
// ports) are left out.
func fdbAges(bridge string) map[string]fdbAge {
	brif := sysNetDir + "/" + bridge + "/brif"
	entries, err := os.ReadDir(brif)
	if err != nil {
		return nil
	}
	ports := map[int]string{}
	for _, e := range entries {
		data, err := os.ReadFile(brif + "/" + e.Name() + "/port_no")
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 0, 64)
		if err != nil {
			continue
		}
		ports[int(n)] = e.Name()
	}
	raw, err := os.ReadFile(sysNetDir + "/" + bridge + "/brforward")
	if err != nil {
		return nil
	}
	return parseBrforward(raw, ports)
}

// parseBrforward reads brforward's records, struct __fdb_entry (16 bytes):
// mac[6], port_no, is_local, ageing_timer_value (u32, hundredths of a
// second, the CPU's own byte order), port_hi, pad, unused[2].
func parseBrforward(raw []byte, ports map[int]string) map[string]fdbAge {
	ages := map[string]fdbAge{}
	for off := 0; off+16 <= len(raw); off += 16 {
		r := raw[off : off+16]
		if r[7] != 0 { // is_local
			continue
		}
		port, ok := ports[int(r[12])<<8|int(r[6])]
		if !ok {
			continue
		}
		mac := net.HardwareAddr(r[0:6]).String()
		age := time.Duration(binary.NativeEndian.Uint32(r[8:12])) * 10 * time.Millisecond
		if cur, ok := ages[mac]; !ok || age < cur.age {
			ages[mac] = fdbAge{port: port, age: age}
		}
	}
	return ages
}

// bridgeAgeing is how long the bridge keeps a quiet MAC (sysfs, in
// hundredths of a second).
func bridgeAgeing(bridge string) time.Duration {
	data, err := os.ReadFile(sysNetDir + "/" + bridge + "/bridge/ageing_time")
	if err != nil {
		return 0
	}
	cs, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || cs <= 0 {
		return 0
	}
	return time.Duration(cs) * 10 * time.Millisecond
}

// onDeviceSubnet: ip lies in a subnet of the very device the ARP row was
// learned on, so a datagram to it leaves through that device and nowhere
// else (an off-subnet address would follow the default route).
func onDeviceSubnet(ip, dev string, subnets []ubus.Subnet) bool {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return false
	}
	for _, s := range subnets {
		if s.Device != dev || s.Mask < 1 || s.Mask > 30 {
			continue
		}
		base := net.ParseIP(s.Address)
		if base == nil || base.To4() == nil {
			continue
		}
		n := net.IPNet{IP: base.Mask(net.CIDRMask(s.Mask, 32)), Mask: net.CIDRMask(s.Mask, 32)}
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// sysNetDir: sysfs's network devices (tests point it elsewhere).
var sysNetDir = "/sys/class/net"

// bridgeDevices: the bridge and the devices stacked on it (its VLAN
// devices, whatever they are named), from sysfs.
func bridgeDevices(bridge string) map[string]bool {
	devs := map[string]bool{bridge: true}
	entries, _ := os.ReadDir(sysNetDir + "/" + bridge)
	for _, e := range entries {
		if name, ok := strings.CutPrefix(e.Name(), "upper_"); ok && name != "" {
			devs[name] = true
		}
	}
	return devs
}

// bridgeArp is the ARP table's MAC -> rows on the bridge and the devices
// stacked on it only: the networks the bridge's MACs live on.
func bridgeArp(bridge string) map[string][]arpRow {
	raw, err := os.ReadFile(arpFilePath)
	if err != nil {
		return map[string][]arpRow{}
	}
	return parseBridgeArp(string(raw), bridgeDevices(bridge))
}

func parseBridgeArp(content string, devs map[string]bool) map[string][]arpRow {
	out := map[string][]arpRow{}
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
		if !devs[dev] {
			continue
		}
		out[mac] = append(out[mac], arpRow{ip: ip, dev: dev})
	}
	return out
}
