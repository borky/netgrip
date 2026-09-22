package server

import (
	"net/http"
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
		for _, name := range []string{sessionCookie, secureSessionCookie} {
			r, _ := http.NewRequest("GET", "/", nil)
			r.AddCookie(&http.Cookie{Name: name, Value: "token"})
			c, err := s.sessionCookie(r)
			if err != nil || c.Value != "token" {
				t.Errorf("secure=%v, cookie %q: got %v, %v", secure, name, c, err)
			}
		}
	}
}
