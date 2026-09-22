package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The session cookie is a bearer token for a panel that can rewrite the
// router's firewall, so over TLS it must carry Secure: without it the browser
// will also send it over plain HTTP, and anything that downgrades a single
// request harvests a usable session.
func TestSessionCookieSecureFollowsTheTransport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secure bool
	}{
		{"served over TLS", true},
		{"served over plain HTTP", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{secure: tc.secure}
			c := s.sessionCookieFor("token", 3600)
			if c.Secure != tc.secure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.secure)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly must always be set: no page script needs to read this")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.Path != "/" {
				t.Errorf("Path = %q, want /", c.Path)
			}
		})
	}
}

// Logging out must actually remove it. A browser replaces a cookie only when
// the name, path and flags match, so clearing it with different attributes
// would leave the old one in place and the session alive.
func TestLogoutCookieMatchesTheOneItReplaces(t *testing.T) {
	s := &Server{secure: true}
	set := s.sessionCookieFor("token", 3600)
	clear := s.sessionCookieFor("", -1)

	if clear.Name != set.Name || clear.Path != set.Path ||
		clear.Secure != set.Secure || clear.HttpOnly != set.HttpOnly ||
		clear.SameSite != set.SameSite {
		t.Fatalf("clearing cookie does not match the one issued:\n  set   %+v\n  clear %+v", set, clear)
	}
	if clear.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative so the browser drops it", clear.MaxAge)
	}
	if clear.Value != "" {
		t.Errorf("Value = %q, want empty", clear.Value)
	}
}

// Switching the panel between HTTP and HTTPS used to lock people out, and
// the password was never the problem: a browser refuses to let an insecure
// origin overwrite a cookie marked Secure, so the old HTTPS cookie blocked
// the new one and the session silently never existed. Different names per
// transport cannot collide.
func TestSessionCookieNameFollowsTheTransport(t *testing.T) {
	plain := (&Server{secure: false}).sessionCookieFor("t", 60)
	tls := (&Server{secure: true}).sessionCookieFor("t", 60)

	if plain.Name == tls.Name {
		t.Fatalf("both transports use %q; the secure one blocks the other", plain.Name)
	}
	// Neither may be the name the panel used to issue. That name may
	// already exist in a browser carrying Secure, and a plaintext origin
	// can neither overwrite nor delete such a cookie - which locked the
	// user out of their own panel with the correct password.
	if plain.Name == legacySessionCookie || tls.Name == legacySessionCookie {
		t.Errorf("a name that was once issued with Secure is unusable from HTTP; "+
			"plain=%q tls=%q legacy=%q", plain.Name, tls.Name, legacySessionCookie)
	}
	if tls.Name != secureSessionCookie {
		t.Errorf("TLS cookie = %q, want the __Secure- prefixed name", tls.Name)
	}
	if !tls.Secure {
		t.Error("a __Secure- prefixed cookie must carry Secure or the browser drops it")
	}
	if plain.Secure {
		t.Error("the plaintext cookie must not claim Secure; it would never be sent")
	}
}

// A session issued before a restart in the same scheme must still be read,
// and the other name is accepted as a fallback so the change of scheme does
// not invalidate a session that is otherwise fine.
func TestSessionCookieIsReadUnderEitherName(t *testing.T) {
	for _, secure := range []bool{false, true} {
		s := &Server{secure: secure}
		for _, name := range []string{httpSessionCookie, secureSessionCookie, legacySessionCookie} {
			r, _ := http.NewRequest("GET", "/", nil)
			r.AddCookie(&http.Cookie{Name: name, Value: "token"})
			c, fallback, err := s.sessionCookie(r)
			// A browser never sends a __Secure- cookie over plain HTTP,
			// so that combination cannot arrive and is not looked for.
			if !secure && name == secureSessionCookie {
				if err == nil {
					t.Errorf("a __Secure- cookie must not be honoured over plain HTTP")
				}
				continue
			}
			if err != nil || c.Value != "token" {
				t.Errorf("secure=%v, cookie %q: got %v, %v", secure, name, c, err)
				continue
			}
			if want := name != s.sessionCookieName(); fallback != want {
				t.Errorf("secure=%v, cookie %q: fallback = %v, want %v", secure, name, fallback, want)
			}
		}
	}
}

// Accepting the other name is what keeps a session alive across the switch,
// but over TLS it must not leave the session on the weaker cookie: a token
// issued in clear may have been read off the LAN, and the __Secure- prefix is
// worth nothing while the plain name stays a permanent alias for it.
func TestALegacyCookieIsMovedToTheSecureNameOverTLS(t *testing.T) {
	s := &Server{secure: true}
	w := httptest.NewRecorder()
	s.reissueUnderCurrentName(w, "token")

	var reissued, expired *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case secureSessionCookie:
			reissued = c
		case httpSessionCookie:
			expired = c
		}
	}
	if reissued == nil || reissued.Value != "token" || !reissued.Secure {
		t.Errorf("the session was not reissued under the secure name: %v", reissued)
	}
	if expired == nil || expired.MaxAge >= 0 {
		t.Errorf("the plaintext cookie must be expired, got %v", expired)
	}
}

// A session from before the names changed must survive, and must not be left
// on the old name: it is read once and moved onto the current one.
func TestALegacySessionIsMovedOntoTheCurrentName(t *testing.T) {
	for _, secure := range []bool{false, true} {
		s := &Server{secure: secure}
		r, _ := http.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: legacySessionCookie, Value: "token"})

		c, fallback, err := s.sessionCookie(r)
		if err != nil || c.Value != "token" {
			t.Fatalf("secure=%v: a legacy session must still be read: %v", secure, err)
		}
		if !fallback {
			t.Errorf("secure=%v: reading the legacy name must be reported as a fallback, "+
				"or the session is never moved off it", secure)
		}

		w := httptest.NewRecorder()
		s.reissueUnderCurrentName(w, c.Value)
		var reissued *http.Cookie
		for _, got := range w.Result().Cookies() {
			if got.Name == s.sessionCookieName() {
				reissued = got
			}
		}
		if reissued == nil || reissued.Value != "token" {
			t.Errorf("secure=%v: session not reissued under %q", secure, s.sessionCookieName())
		}
	}
}
