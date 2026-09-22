package server

import (
	"testing"
	"time"
)

// The policy, read as a table. Typos are free; after that the wait doubles
// and then stops growing, so guessing is hopeless without locking out an
// administrator who genuinely forgot which password it was.
func TestLoginDelayPolicy(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
		why      string
	}{
		{1, 0, "a typo costs nothing"},
		{2, 0, "so does a second"},
		{3, 0, "and the third, which is the last free one"},
		{4, time.Second, "the wait starts"},
		{5, 2 * time.Second, "and doubles"},
		{6, 4 * time.Second, ""},
		{7, 8 * time.Second, ""},
		{8, 16 * time.Second, ""},
		{9, loginMaxDelay, "capped"},
		{50, loginMaxDelay, "still capped, and no overflow"},
		{1000, loginMaxDelay, "the shift must not wrap to something small"},
	} {
		if got := loginDelay(tc.failures); got != tc.want {
			t.Errorf("after %d failures: %v, want %v (%s)", tc.failures, got, tc.want, tc.why)
		}
	}
}

// The rate an attacker is left with is the point of the whole file: at the
// cap, a couple of attempts a minute rather than as fast as rpcd answers.
func TestSustainedGuessingIsSlowedToACrawl(t *testing.T) {
	if perMinute := int(time.Minute / loginMaxDelay); perMinute > 3 {
		t.Errorf("a stuck attacker still gets %d attempts a minute", perMinute)
	}
}

func TestThrottleBlocksAndThenRelents(t *testing.T) {
	now := time.Now()
	tr := newLoginThrottle()
	tr.now = func() time.Time { return now }

	const addr = "192.0.2.10"
	for i := 0; i < loginFreeAttempts; i++ {
		tr.failed(addr)
		if wait := tr.retryAfter(addr); wait != 0 {
			t.Fatalf("failure %d should still be free, got %v", i+1, wait)
		}
	}
	tr.failed(addr)
	wait := tr.retryAfter(addr)
	if wait <= 0 {
		t.Fatal("the first failure past the free ones must impose a wait")
	}

	// Time passes: the address may try again.
	now = now.Add(wait + time.Millisecond)
	if got := tr.retryAfter(addr); got != 0 {
		t.Errorf("after the wait elapsed: %v, want 0", got)
	}
}

// One address being slowed must not slow anybody else, or an attacker locks
// the administrator out by failing a few logins of their own.
func TestThrottleIsPerAddress(t *testing.T) {
	tr := newLoginThrottle()
	for i := 0; i < 20; i++ {
		tr.failed("192.0.2.10")
	}
	if tr.retryAfter("192.0.2.10") <= 0 {
		t.Fatal("the guessing address is not being slowed")
	}
	if got := tr.retryAfter("198.51.100.7"); got != 0 {
		t.Errorf("an unrelated address must be unaffected, got %v", got)
	}
}

// Getting in clears the record: the budget counts consecutive failures.
func TestASuccessfulLoginForgetsTheFailures(t *testing.T) {
	tr := newLoginThrottle()
	for i := 0; i < 10; i++ {
		tr.failed("192.0.2.10")
	}
	tr.succeeded("192.0.2.10")
	if got := tr.retryAfter("192.0.2.10"); got != 0 {
		t.Errorf("after a successful login: %v, want 0", got)
	}
}

// The map is reachable by anyone who can open a socket, so it must not be a
// way to spend the router's memory.
func TestTheTableStaysBounded(t *testing.T) {
	now := time.Now()
	tr := newLoginThrottle()
	tr.now = func() time.Time { return now }

	for i := 0; i < loginMaxTracked*3; i++ {
		// A different address every time, as an attacker spraying would.
		tr.failed(addrN(i))
		now = now.Add(time.Millisecond)
	}
	if len(tr.seen) > loginMaxTracked {
		t.Errorf("tracking %d addresses, cap is %d", len(tr.seen), loginMaxTracked)
	}
}

// Records outlive their last attempt only for a while.
func TestOldRecordsAreForgotten(t *testing.T) {
	now := time.Now()
	tr := newLoginThrottle()
	tr.now = func() time.Time { return now }

	tr.failed("192.0.2.10")
	now = now.Add(loginForget + time.Minute)
	tr.failed("198.51.100.7") // adding an address is what triggers the prune
	if _, still := tr.seen["192.0.2.10"]; still {
		t.Error("a record with no attempt for an hour should have been dropped")
	}
}

func addrN(i int) string {
	return "198.51.100." + string(rune('0'+i%10)) + "-" + string(rune('a'+i/10%26)) +
		"-" + string(rune('a'+i/260%26))
}
