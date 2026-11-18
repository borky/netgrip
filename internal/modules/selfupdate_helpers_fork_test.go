package modules

import (
	"os"
	"path/filepath"
	"testing"
)

// TestForkSkipsHealRegister: the fork never installs the registry heal (it
// would pull upstream's package over this build); the rule restorer is still
// kept current.
func TestForkSkipsHealRegister(t *testing.T) {
	dir := t.TempDir()
	old := helperScriptDir
	helperScriptDir = dir
	t.Cleanup(func() { helperScriptDir = old })

	syncHelperScripts("startup", "v0.79.0")

	if _, err := os.Stat(filepath.Join(dir, "netgrip-heal-register")); !os.IsNotExist(err) {
		t.Errorf("heal-register installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "netgrip-restore-rules")); err != nil {
		t.Errorf("restore-rules not installed: %v", err)
	}
}
