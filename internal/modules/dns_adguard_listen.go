package modules

// FORK: what the running AdGuard Home process actually listens on, read from
// /proc rather than assumed from its config. Two things depend on it:
//
//   - whether AdGuard filters: it can answer DNS on :53 itself, with dnsmasq
//     moved aside, instead of sitting behind dnsmasq (NetGrip's own handoff).
//     Both filter; only the second is visible in dnsmasq's config.
//   - where its web UI is: the port in its config, confirmed by the process
//     really listening there.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// adGuardProcessName is the command name of the AdGuard Home binary.
const adGuardProcessName = "AdGuardHome"

// adGuardListeners is the set of ports a process listens on.
type adGuardListeners struct {
	TCP map[int]bool
	UDP map[int]bool
}

// probeAdGuardListeners returns the TCP and UDP ports the running AdGuard
// Home process listens on, and false when no such process runs or /proc
// cannot be read.
func probeAdGuardListeners() (adGuardListeners, bool) {
	inodes := map[string]bool{}
	found := false
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range procs {
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != adGuardProcessName {
			continue
		}
		found = true
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
	}
	if !found {
		return adGuardListeners{}, false
	}
	l := adGuardListeners{TCP: map[int]bool{}, UDP: map[int]bool{}}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		for p := range listeningPorts(readProcNet(f), inodes, true) {
			l.TCP[p] = true
		}
	}
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		for p := range listeningPorts(readProcNet(f), inodes, false) {
			l.UDP[p] = true
		}
	}
	return l, true
}

func readProcNet(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// procNetListenState is the "st" column of a listening TCP socket.
const procNetListenState = "0A"

// listeningPorts parses a /proc/net/{tcp,udp}[6] table and returns the local
// ports of the sockets whose inode is in inodes. For TCP only listening
// sockets count; UDP has no listen state, and a bound socket is one.
func listeningPorts(table string, inodes map[string]bool, tcp bool) map[int]bool {
	ports := map[int]bool{}
	sc := bufio.NewScanner(strings.NewReader(table))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		// sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode
		if len(f) < 10 || !inodes[f[9]] {
			continue
		}
		if tcp && f[3] != procNetListenState {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		if p, err := strconv.ParseInt(f[1][i+1:], 16, 32); err == nil && p > 0 {
			ports[int(p)] = true
		}
	}
	return ports
}

// adGuardWebPort picks the port AdGuard's web UI is on: the configured one
// when the process listens there, else a TCP port it does listen on that is
// not one of its DNS ports, else the configured one, else the historical
// default. observed=false means the process could not be inspected.
func adGuardWebPort(configured int, l adGuardListeners, observed bool, dnsPorts ...int) int {
	if observed {
		if configured > 0 && l.TCP[configured] {
			return configured
		}
		skip := map[int]bool{853: true} // DNS-over-TLS
		for _, p := range dnsPorts {
			skip[p] = true
		}
		best := 0
		for p := range l.TCP {
			if !skip[p] && (best == 0 || p < best) {
				best = p
			}
		}
		if best > 0 {
			return best
		}
	}
	if configured > 0 {
		return configured
	}
	return adGuardDefaultWebPort
}
