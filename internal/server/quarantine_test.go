package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gnacho/netgrip/internal/modules"
)

// Uncommitted changes from elsewhere: no snapshot (it would carry them),
// no change, and a 409 that says so.
func TestRunRiskyRefusesPendingChangesBeforeSnapshotting(t *testing.T) {
	oPending, oSnap := quarantinePendingCheck, snapshotFn
	t.Cleanup(func() { quarantinePendingCheck, snapshotFn = oPending, oSnap })
	quarantinePendingCheck = func([]string) error { return &modules.QPendingError{Pkg: "dhcp", First: "dhcp.x.y='z'"} }
	snapshots := 0
	snapshotFn = func(string) (string, error) { snapshots++; return "", nil }
	applied := false
	rec := httptest.NewRecorder()
	(&Server{}).runRisky(rec, qWifiConfigs, nil, func() (modules.QuarantineProbe, error) {
		applied = true
		return modules.QuarantineProbe{}, nil
	})
	if rec.Code != http.StatusConflict || snapshots != 0 || applied {
		t.Fatalf("code %d, snapshots %d, applied %v", rec.Code, snapshots, applied)
	}
}

// A refusal from the module changed nothing: restoring the snapshots
// would commit whatever they carried.
func TestRunRiskyDoesNotRevertARefusal(t *testing.T) {
	oPending, oSnap, oRevert := quarantinePendingCheck, snapshotFn, revertFn
	t.Cleanup(func() { quarantinePendingCheck, snapshotFn, revertFn = oPending, oSnap, oRevert })
	quarantinePendingCheck = func([]string) error { return nil }
	snapshotFn = func(string) (string, error) { return "", nil }
	reverted := false
	revertFn = func(map[string]string) error { reverted = true; return nil }
	rec := httptest.NewRecorder()
	(&Server{}).runRisky(rec, qFirewallConfigs, nil, func() (modules.QuarantineProbe, error) {
		return modules.QuarantineProbe{}, &modules.QPendingError{Pkg: "firewall", First: "x"}
	})
	if reverted {
		t.Fatal("a refusal was reverted")
	}
	// A refusal wrapped by a later step came after something changed.
	(&Server{}).runRisky(httptest.NewRecorder(), qFirewallConfigs, nil, func() (modules.QuarantineProbe, error) {
		return modules.QuarantineProbe{}, fmt.Errorf("hooking failed: %w", &modules.QPendingError{Pkg: "firewall", First: "x"})
	})
	if !reverted {
		t.Fatal("a refusal after changes were made was not reverted")
	}
	reverted = false
	// Any other failure is reverted too.
	(&Server{}).runRisky(httptest.NewRecorder(), qFirewallConfigs, nil, func() (modules.QuarantineProbe, error) {
		return modules.QuarantineProbe{}, errors.New("boom")
	})
	if !reverted {
		t.Fatal("a failed change was not reverted")
	}
}

// Pending changes in an optional config (unrelated Wi-Fi edits while only
// the zones change): not refused, and not snapshotted.
func TestRunRiskyLeavesDirtyOptionalConfigsOut(t *testing.T) {
	oPending, oSnap := quarantinePendingCheck, snapshotFn
	t.Cleanup(func() { quarantinePendingCheck, snapshotFn = oPending, oSnap })
	quarantinePendingCheck = func(pkgs []string) error {
		for _, p := range pkgs {
			if p == "wireless" {
				return &modules.QPendingError{Pkg: p, First: "x"}
			}
		}
		return nil
	}
	var snapped []string
	snapshotFn = func(c string) (string, error) { snapped = append(snapped, c); return "", nil }
	applied := false
	rec := httptest.NewRecorder()
	(&Server{}).runRisky(rec, qFirewallConfigs, qWifiOptional, func() (modules.QuarantineProbe, error) {
		applied = true
		return modules.QuarantineProbe{}, errors.New("boom")
	})
	if !applied {
		t.Fatal("refused over an optional config")
	}
	for _, c := range snapped {
		if c == "wireless" {
			t.Fatal("a config with pending changes was snapshotted")
		}
	}
}
