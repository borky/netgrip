package modules

import "testing"

// The shape /proc/net/tcp has on a router where dropbear is bound to one
// interface (`option Interface 'lan'`), which is how SSH is kept off the WAN.
// Addresses are documentation-range; what matters is the pattern:
//
//   - 010200C0:0016 — port 0x16 = 22, on an interface address, state 0A
//     (LISTEN). Nothing is bound to 0100007F (127.0.0.1), so a loopback dial
//     is refused while SSH works perfectly. That is the case that used to
//     roll back every save on the Access card.
//   - 00000000:0050 — the ordinary wildcard listener, port 80.
//   - 010200C0:1F90 in state 01 — an ESTABLISHED session to port 8080, which
//     must not be mistaken for something listening there.
const procNetTCPBoundToOneInterface = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 010200C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17734057 1 d0dce70a 100 0 0 10 5
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 32889784 1 2ec2fc73 100 0 0 10 5
   2: 010200C0:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17734100 1 14c17c58 100 0 0 10 5
   3: 010200C0:1F90 020200C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 17734200 1 14c17c59 100 0 0 10 5
`

// The bug: a daemon listening only on an interface address is healthy, and
// the check has to say so.
func TestListenerFoundWhenBoundToOneInterface(t *testing.T) {
	if !hasListenerOnPort(procNetTCPBoundToOneInterface, 22) {
		t.Fatal("SSH bound to one interface must count as listening; this is the case that rolled back good saves")
	}
}

// Ports nothing is listening on must not be reported as live, or the
// healthcheck stops being a check at all.
func TestNoListenerOnAnUnusedPort(t *testing.T) {
	for _, port := range []int{2222, 443, 8090} {
		if hasListenerOnPort(procNetTCPBoundToOneInterface, port) {
			t.Errorf("port %d is not in the table but was reported listening", port)
		}
	}
}

// An established connection to a port is not a listener on it.
func TestEstablishedConnectionIsNotAListener(t *testing.T) {
	if hasListenerOnPort(procNetTCPBoundToOneInterface, 8080) {
		t.Error("state 01 is ESTABLISHED, not LISTEN")
	}
}

// The ordinary wildcard case must keep working.
func TestListenerFoundOnWildcardAddress(t *testing.T) {
	if !hasListenerOnPort(procNetTCPBoundToOneInterface, 80) {
		t.Error("a wildcard listener must be found too")
	}
}

// Only a header, or garbage, must be false rather than a panic:
// /proc/net/tcp6 is absent on a kernel built without IPv6.
func TestEmptyOrGarbageTable(t *testing.T) {
	for _, tc := range []string{"", "sl  local_address rem_address   st\n", "nonsense\nlines here\n"} {
		if hasListenerOnPort(tc, 22) {
			t.Errorf("unexpected listener reported for %q", tc)
		}
	}
}
