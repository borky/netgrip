package modules

import "testing"

// Real `brctl showmacs br-lan` output from a VLAN-filtered bridge: the
// switch on port 1 trunks seven VLANs, so its MAC is listed once per VLAN
// with no column to tell them apart. It showed up seven times in Clients.
const brctlShowmacsWithVlanDuplicates = `port no	mac addr		is local?	ageing timer
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:11	no		  18.96
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:11	no		  26.12
  1	02:00:00:00:00:12	yes		   0.00
  1	02:00:00:00:00:13	no		  11.43
  2	02:00:00:00:00:14	no		   3.21
`

func TestParseBrctlShowmacsCollapsesPerVLANDuplicates(t *testing.T) {
	fdb := parseBrctlShowmacs(brctlShowmacsWithVlanDuplicates, map[int]string{1: "lan2", 2: "lan1"})

	count := 0
	for _, mac := range fdb["lan2"] {
		if mac == "02:00:00:00:00:11" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("the switch MAC appears %d times on lan2, want 1 (got %v)", count, fdb["lan2"])
	}
	if len(fdb["lan2"]) != 2 {
		t.Fatalf("lan2 = %v, want the switch and one more device (the local MAC is skipped)", fdb["lan2"])
	}
	if len(fdb["lan1"]) != 1 {
		t.Fatalf("lan1 = %v, want one device", fdb["lan1"])
	}
}

// The bridge's own MAC ("is local? yes") is not a client.
func TestParseBrctlShowmacsSkipsLocalMACs(t *testing.T) {
	fdb := parseBrctlShowmacs(brctlShowmacsWithVlanDuplicates, map[int]string{1: "lan2"})
	for _, mac := range fdb["lan2"] {
		if mac == "02:00:00:00:00:12" {
			t.Fatal("the bridge's own local MAC must not be reported as a client")
		}
	}
}

// Loop detection relies on a MAC being reported on every port it was
// learned on, so dedup must be per port, not global.
func TestParseBrctlShowmacsKeepsAMACSeenOnTwoPorts(t *testing.T) {
	out := `port no	mac addr		is local?	ageing timer
  1	aa:bb:cc:dd:ee:ff	no		   1.00
  1	aa:bb:cc:dd:ee:ff	no		   1.00
  2	aa:bb:cc:dd:ee:ff	no		   2.00
`
	fdb := parseBrctlShowmacs(out, map[int]string{1: "lan1", 2: "lan2"})
	if len(fdb["lan1"]) != 1 || len(fdb["lan2"]) != 1 {
		t.Fatalf("fdb = %v, want the MAC once on each of the two ports", fdb)
	}
}

func TestParseBrctlShowmacsIgnoresUnknownPorts(t *testing.T) {
	fdb := parseBrctlShowmacs(brctlShowmacsWithVlanDuplicates, map[int]string{9: "lan9"})
	if len(fdb) != 0 {
		t.Fatalf("fdb = %v, want nothing for unmapped port numbers", fdb)
	}
}
