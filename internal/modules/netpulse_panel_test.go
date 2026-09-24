package modules

// FORK: tests for netpulse_panel.go, a fork-only file.

import "testing"

func resetPanelState(t *testing.T) {
	t.Helper()
	panelSPKISource.Store(nil)
	panelServesTLS = false
	t.Cleanup(func() {
		panelSPKISource.Store(nil)
		panelServesTLS = false
	})
}

// The window a review caught: the panel is started with -https, the agent is
// already running, and the certificate is not open yet. The panel must report
// HTTPS with no key - which the monitoring side answers by sending nothing -
// and never plain HTTP, which made it send the executor token in clear.
func TestAnHTTPSPanelIsHTTPSBeforeItHasAKey(t *testing.T) {
	resetPanelState(t)
	SetPanelServesTLS(true)

	if !panelServesTLS {
		t.Fatal("the TLS flag was not recorded")
	}
	if got := panelSPKIHook(); got != "" {
		t.Fatalf("with no certificate open yet the hook returned %q", got)
	}
}

// Once main has opened the certificate the agent reads the key live at every
// push, so a rotation moves the pin on the next report.
func TestPanelSPKIHookIsReadLive(t *testing.T) {
	resetPanelState(t)
	SetPanelServesTLS(true)

	current := "aa11"
	SetPanelTLS(func() string { return current })
	if got := panelSPKIHook(); got != "aa11" {
		t.Fatalf("hook = %q, want the served key", got)
	}
	current = "bb22"
	if got := panelSPKIHook(); got != "bb22" {
		t.Fatalf("hook = %q after rotation; it must be read live, not captured", got)
	}
}

// A panel on plain HTTP reports no TLS and no key.
func TestAPlainPanelReportsNeither(t *testing.T) {
	resetPanelState(t)
	SetPanelServesTLS(false)
	if panelServesTLS || panelSPKIHook() != "" {
		t.Fatal("a plain-HTTP panel reported TLS state")
	}
}
