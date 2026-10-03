// loginthrottle.go — slows password guessing against the panel's login.
//
// The panel authenticates with the router's ROOT password, and nothing
// rate-limited the endpoint: anything on the LAN could try passwords as fast
// as rpcd would answer them. This does not make a weak password strong. It
// turns thousands of guesses a second into a couple a minute, which is the
// difference between a short password falling in an afternoon and not.
//
// Per source address, not global, deliberately: a global counter would let
// anyone on the LAN lock the administrator out of their own router by
// failing a few logins, which trades one denial of service for another. The
// cost is that an attacker with several addresses gets several budgets -
// they must still complete a TCP handshake from each, so the addresses are
// real ones, and anyone able to forge those at will on the LAN has easier
// paths than guessing the password.
package server

import (
	"sync"
	"time"
)

const (
	// loginFreeAttempts: mistyping a password should cost nothing. Only
	// after this many consecutive failures does the wait start.
	loginFreeAttempts = 3

	// loginMaxDelay caps the wait. Long enough that guessing is hopeless
	// (about two attempts a minute), short enough that the administrator
	// who genuinely forgot which password it was is not locked out for the
	// afternoon.
	loginMaxDelay = 30 * time.Second

	// loginForget: how long a record outlives its last attempt.
	loginForget = time.Hour

	// loginMaxTracked bounds the memory an unauthenticated caller can make
	// the panel spend. A router has tens of megabytes, and this map must
	// never be a way to eat them.
	loginMaxTracked = 1024
)

type loginAttempts struct {
	failures     int
	blockedUntil time.Time
	touched      time.Time
}

type loginThrottle struct {
	mu   sync.Mutex
	seen map[string]*loginAttempts
	now  func() time.Time // replaced in tests
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{seen: map[string]*loginAttempts{}, now: time.Now}
}

// retryAfter is how long this address must wait, or zero if it may try now.
func (t *loginThrottle) retryAfter(addr string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.seen[addr]
	if !ok {
		return 0
	}
	if wait := rec.blockedUntil.Sub(t.now()); wait > 0 {
		return wait
	}
	return 0
}

// failed records a rejected attempt and returns how long the address must
// now wait before the next one.
func (t *loginThrottle) failed(addr string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	rec, ok := t.seen[addr]
	if !ok {
		t.prune(now)
		rec = &loginAttempts{}
		t.seen[addr] = rec
	}
	rec.failures++
	rec.touched = now
	delay := loginDelay(rec.failures)
	rec.blockedUntil = now.Add(delay)
	return delay
}

// succeeded forgets an address: the budget is for consecutive failures, so
// getting in resets it.
func (t *loginThrottle) succeeded(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, addr)
}

// prune keeps the map bounded. Called only when adding an address, so the
// work is paid by whoever causes it. Call with t.mu held.
func (t *loginThrottle) prune(now time.Time) {
	for addr, rec := range t.seen {
		if now.Sub(rec.touched) > loginForget {
			delete(t.seen, addr)
		}
	}
	if len(t.seen) < loginMaxTracked {
		return
	}
	// Still full of live records: drop the least recently active, so an
	// attacker spraying addresses cannot push out everyone's state and
	// cannot grow the map either.
	var oldest string
	var oldestAt time.Time
	for addr, rec := range t.seen {
		if oldest == "" || rec.touched.Before(oldestAt) {
			oldest, oldestAt = addr, rec.touched
		}
	}
	delete(t.seen, oldest)
}

// loginDelay is the wait after n consecutive failures. Pure, so the policy
// can be read and tested without a clock: nothing, nothing, nothing, then
// 1s, 2s, 4s, 8s, 16s, and 30s from then on.
func loginDelay(failures int) time.Duration {
	n := failures - loginFreeAttempts
	if n <= 0 {
		return 0
	}
	if n > 8 {
		n = 8 // past the cap anyway, and shifting further overflows
	}
	if d := time.Second << (n - 1); d < loginMaxDelay {
		return d
	}
	return loginMaxDelay
}
