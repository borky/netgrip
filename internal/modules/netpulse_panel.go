package modules

// FORK: this file exists only in the fork, so the change to upstream's
// netpulse_agent.go stays at one field in the agent's options.

import "sync/atomic"

// panelServesTLS says the panel was started with -https. It is set from the
// command line before anything starts and only read afterwards, so it needs no
// lock. It is reported separately from the key on purpose: an HTTPS panel
// whose certificate is not open yet must still say it is on HTTPS, so the
// monitoring side sends it nothing rather than sending in clear.
var panelServesTLS bool

// SetPanelServesTLS records whether the panel serves HTTPS. Call it before the
// embedded agent starts.
func SetPanelServesTLS(on bool) { panelServesTLS = on }

// panelSPKISource answers for the certificate the panel is serving. It is set
// once main has opened the certificate, which happens after the agent has
// already started, and read by the agent at every push - from another
// goroutine, hence atomic.
var panelSPKISource atomic.Pointer[func() string]

// SetPanelTLS tells the embedded agent the panel serves HTTPS, and how to read
// the key of the certificate it is serving. The monitoring side pins that key
// before it sends the executor token to this panel, and builds its link with
// https.
func SetPanelTLS(spki func() string) {
	if spki != nil {
		panelSPKISource.Store(&spki)
	}
}

// panelSPKIHook is what the agent calls at each push: the current key, or ""
// if there is none to report yet.
func panelSPKIHook() string {
	if f := panelSPKISource.Load(); f != nil {
		return (*f)()
	}
	return ""
}
