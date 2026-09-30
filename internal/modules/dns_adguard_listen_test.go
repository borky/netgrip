package modules

// FORK: tests for dns_adguard_listen.go and the AdGuard web port parsing.
// Tables and configs are invented.

import "testing"

// A /proc/net/tcp table: AdGuard (inodes 111, 112) listens on 53 (0x35) and
// 8080 (0x1F90); 113 is one of its established connections; 999 belongs to
// another process listening on 22.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 112 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 113 1 0000000000000000 20 4 30 10 -1
   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0
`

const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 114 2 0000000000000000 0
  101: 00000000:0036 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 998 2 0000000000000000 0
`

func TestListeningPortsKeepsOnlyTheProcessesOwn(t *testing.T) {
	ours := map[string]bool{"111": true, "112": true, "113": true, "114": true}
	tcp := listeningPorts(procTCP, ours, true)
	if len(tcp) != 2 || !tcp[53] || !tcp[8080] {
		t.Fatalf("tcp: %v, want 53 and 8080 (not the established 50000, not another process's 22)", tcp)
	}
	udp := listeningPorts(procUDP, ours, false)
	if len(udp) != 1 || !udp[53] {
		t.Fatalf("udp: %v, want only 53 (54 is another process's)", udp)
	}
}

func TestParseAdGuardWebPort(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want int
	}{
		"current":     {"http:\n  pprof:\n    port: 6060\n  address: 0.0.0.0:8080\n  session_ttl: 720h\ndns:\n  port: 53\n", 8080},
		"quoted ipv6": {"http:\n  address: \"[::]:8443\"\n", 8443},
		"legacy":      {"bind_host: 0.0.0.0\nbind_port: 3001\ndns:\n  port: 5353\n", 3001},
		// dns.port and http.pprof.port must not be read as the web port.
		"none": {"dns:\n  port: 53\nhttp:\n  pprof:\n    port: 6060\n", 0},
	} {
		if got := parseAdGuardWebPort([]byte(tc.yaml)); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}

func TestAdGuardWebPortPrefersWhatIsListening(t *testing.T) {
	l := adGuardListeners{TCP: map[int]bool{53: true, 8080: true}, UDP: map[int]bool{53: true}}
	for name, tc := range map[string]struct {
		configured int
		observed   bool
		want       int
	}{
		"configured and listening":          {8080, true, 8080},
		"configured but not listening":      {3000, true, 8080},
		"nothing configured, one candidate": {0, true, 8080},
		"process not inspectable":           {8080, false, 8080},
		"nothing known at all":              {0, false, adGuardDefaultWebPort},
	} {
		if got := adGuardWebPort(tc.configured, l, tc.observed, 53); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}
