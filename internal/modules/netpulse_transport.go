package modules

// FORK: NetGrip's own requests to the NetPulse server - enrolment, the
// executor token, config backups - reach it the way the embedded agent does:
// pinned to the server's key when the server is on https.

import (
	"net/http"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/runtime"
)

// netPulseClient is a client for requests to the NetPulse server at server.
// On https it pins pins (NETPULSE_SERVER_FP: the server's key or its CA's);
// on plain http there is nothing to pin. It never follows a redirect, which
// would carry the request's token to another address.
func netPulseClient(server, pins string, timeout time.Duration) (*http.Client, error) {
	tr, err := runtime.ServerTransport(strings.TrimRight(server, "/"), pins)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// sameNetPulseServer reports whether a and b address the same server, so a
// pin configured for one applies to the other.
func sameNetPulseServer(a, b string) bool {
	a, b = strings.TrimRight(a, "/"), strings.TrimRight(b, "/")
	return a != "" && strings.EqualFold(a, b)
}
