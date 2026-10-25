package modules

// FORK: the running binary is not freed by its unlink, so it never counts
// towards a self-update's space budget.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheRunningBinaryIsNotCountedAsFreed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Skip("executable not stat-able")
	}
	if !isRunningBinary(fi) {
		t.Fatal("the test binary itself was not recognised as the running binary")
	}

	other := filepath.Join(t.TempDir(), "netgrip")
	if err := os.WriteFile(other, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	ofi, _ := os.Stat(other)
	if isRunningBinary(ofi) {
		t.Fatal("a binary that is not running was taken for the running one")
	}
}
