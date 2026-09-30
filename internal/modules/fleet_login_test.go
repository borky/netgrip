package modules

// FORK: tests for fleet_login.go, against a stand-in for the panel's login
// and session handling.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// panelStandIn answers like the panel: /api/login gives 204 and a session
// cookie for the right password, and the API wants that cookie, nothing else.
func panelStandIn(password, cookieName string, secure bool) http.Handler {
	const session = "session-token"
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username, Password string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Username != "root" || req.Password != password {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: session, Path: "/", HttpOnly: true, Secure: secure})
		w.WriteHeader(http.StatusNoContent)
	})
	authed := func(r *http.Request) bool {
		c, err := r.Cookie(cookieName)
		return err == nil && c.Value == session && r.Header.Get("Authorization") == ""
	}
	mux.HandleFunc("GET /api/selfupdate", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(SelfUpdateCheck{Current: "1.0.0", Latest: "1.1.0", Available: true})
	})
	mux.HandleFunc("POST /api/selfupdate", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func TestFleetLoginUsesThePanelSessionOverHTTP(t *testing.T) {
	srv := httptest.NewServer(panelStandIn("dummy-pass", "netgrip_http_session", false))
	defer srv.Close()
	node := &FleetNode{ID: "n1", Address: hostPort(srv.URL), Password: "dummy-pass"}

	st, _ := checkNodeUpdateLearning(node)
	if !st.Reachable || st.Error != "" || st.LatestVersion != "1.1.0" || !st.UpdateAvailable {
		t.Fatalf("status = %+v, want reachable with the peer's versions", st)
	}
}

func TestFleetLoginUsesThePanelSessionOverHTTPS(t *testing.T) {
	srv, _ := tlsPeerServing(t, panelStandIn("dummy-pass", "__Secure-netgrip_session", true))
	node := &FleetNode{ID: "n1", Address: hostPort(srv.URL), Password: "dummy-pass"}

	st, learned := checkNodeUpdateLearning(node)
	if !st.Reachable || st.Error != "" || !st.TLS || !learned {
		t.Fatalf("status = %+v learned=%v, want reachable over pinned HTTPS", st, learned)
	}
	base, client, _, err := fleetPeerClient(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, err = fleetPanelLogin(client, base, node.Password)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(base+"/api/selfupdate", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("update with the session: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestFleetLoginReportsAWrongPassword(t *testing.T) {
	srv := httptest.NewServer(panelStandIn("dummy-pass", "netgrip_http_session", false))
	defer srv.Close()
	node := &FleetNode{ID: "n1", Address: hostPort(srv.URL), Password: "not-it"}

	st, _ := checkNodeUpdateLearning(node)
	if st.Reachable || !strings.Contains(st.Error, "password was refused") {
		t.Fatalf("status = %+v, want the refused password named", st)
	}
}
