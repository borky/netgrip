package modules

// FORK: tests for AdGuard set up as the network's DNS server, and for
// config rewrites keeping what lets AdGuard read its file.

import (
	"os"
	"strings"
	"testing"
)

// A config answering on :53 is direct setup even with AdGuard stopped: no
// socket says so then, and a handoff or a provisioning started in that
// window would rewrite the only DNS server's config.
func TestAdGuardDirectSetupFollowsTheConfigWhileStopped(t *testing.T) {
	pinAdGuardPaths(t)
	for _, tc := range []struct {
		port string
		want bool
	}{
		{"53", true},
		{"5353", false},
	} {
		yaml := strings.Replace(adGuardHandYAML, "port: 5353", "port: "+tc.port, 1)
		if err := os.WriteFile(adGuardConfigPath, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		// No AdGuard process runs here, so only the config can say it.
		if got := adGuardDirectSetup(); got != tc.want {
			t.Errorf("dns port %s: direct = %v, want %v", tc.port, got, tc.want)
		}
	}
}

// The atomic rewrite replaces the file; it has to carry the old one's mode,
// or a config AdGuard reads through its group becomes unreadable to it.
func TestWriteAdGuardYAMLKeepsTheMode(t *testing.T) {
	pinAdGuardPaths(t)
	if err := os.WriteFile(adGuardConfigPath, []byte(adGuardHandYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(adGuardConfigPath, 0o640); err != nil { // past the umask
		t.Fatal(err)
	}
	if err := writeAdGuardYAML(adGuardConfigPath, []byte(adGuardHandYAML+"# rewritten\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(adGuardConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode after rewrite = %v, want 0640", st.Mode().Perm())
	}
}
