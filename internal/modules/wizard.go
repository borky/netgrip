package modules

import (
	"fmt"
	"os/exec"
	"strings"
)

type WizardState struct {
	Completed bool   `json:"completed"`
	Mode      string `json:"mode"`
}

func ProbeWizard() *WizardState {
	completed := false
	if out, err := exec.Command("uci", "-q", "get", "netgrip.wizard.completed").Output(); err == nil {
		completed = strings.TrimSpace(string(out)) == "1"
	}
	mode := ProbeMode().Mode
	return &WizardState{Completed: completed, Mode: mode}
}

func CompleteWizard() error {
	// Both branches used a bare `uci import`, which REPLACES the package:
	// the second one, holding only the wizard section, took netgrip.main -
	// the panel's port and TLS settings - and netgrip.selfupdate with it.
	if err := EnsureNetgripSection("wizard", "wizard"); err != nil {
		return err
	}
	out, err := exec.Command("uci", "set", "netgrip.wizard.completed=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("set wizard completed: %s", strings.TrimSpace(string(out)))
	}
	return exec.Command("uci", "commit", "netgrip").Run()
}
