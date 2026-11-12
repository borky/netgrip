package server

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// stubRevert replaces revertFn for one test and records what it was asked
// to restore.
func stubRevert(t *testing.T, err error) <-chan map[string]string {
	t.Helper()
	got := make(chan map[string]string, 4)
	orig := revertFn
	revertFn = func(s map[string]string) error {
		got <- s
		return err
	}
	t.Cleanup(func() { revertFn = orig })
	return got
}

func TestArmConfirmAutoRevertsAfterTimeout(t *testing.T) {
	reverted := stubRevert(t, nil)
	s := &Server{}
	id, expires := s.armConfirm(map[string]string{"network": "n0"}, 20*time.Millisecond)
	if id == "" || !expires.After(time.Now()) {
		t.Fatalf("id %q expires %v", id, expires)
	}
	select {
	case snap := <-reverted:
		if snap["network"] != "n0" {
			t.Fatalf("reverted %v", snap)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected revert to fire after timeout")
	}
	if _, _, ok := s.confirmStatus(); ok {
		t.Fatal("expected confirm to be cleared after auto-revert")
	}
}

func TestKeepConfirmCancelsAutoRevert(t *testing.T) {
	reverted := stubRevert(t, nil)
	s := &Server{}
	id, _ := s.armConfirm(map[string]string{"network": "n0"}, 20*time.Millisecond)
	if !s.keepConfirm(id) {
		t.Fatal("expected keep to find the pending confirm")
	}
	select {
	case <-reverted:
		t.Fatal("revert fired after keep")
	case <-time.After(80 * time.Millisecond):
	}
}

func TestRevertConfirmRunsImmediately(t *testing.T) {
	reverted := stubRevert(t, nil)
	s := &Server{}
	id, _ := s.armConfirm(map[string]string{"firewall": "f0"}, time.Minute)
	found, err := s.revertConfirm(id)
	if !found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	select {
	case <-reverted:
	case <-time.After(time.Second):
		t.Fatal("expected revert to run immediately")
	}
}

func TestKeepUnknownConfirmReturnsFalse(t *testing.T) {
	s := &Server{}
	if s.keepConfirm("does-not-exist") {
		t.Fatal("keep on unknown id should return false")
	}
	if found, _ := s.revertConfirm("does-not-exist"); found {
		t.Fatal("revert on unknown id should return false")
	}
}

// A second change while the first is unconfirmed joins its window: a revert
// restores the state before the FIRST change, for every config either
// touched. Before, the first change was silently kept.
func TestSecondChangeJoinsThePendingWindow(t *testing.T) {
	reverted := stubRevert(t, nil)
	s := &Server{}
	firstID, _ := s.armConfirm(map[string]string{"network": "before-first"}, time.Minute)
	secondID, _ := s.armConfirm(map[string]string{"network": "after-first", "wireless": "w0"}, time.Minute)

	if id, _, ok := s.confirmStatus(); !ok || id != secondID {
		t.Fatalf("active confirm %q, want %q", id, secondID)
	}
	_ = firstID // still accepted: see TestKeepWithAnAbsorbedID
	if found, _ := s.revertConfirm(secondID); !found {
		t.Fatal("expected to revert the joined window")
	}
	snap := <-reverted
	want := map[string]string{"network": "before-first", "wireless": "w0"}
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("reverted %v, want %v", snap, want)
	}
}

// A failed revert is reported: by the rollback endpoint's result and by the
// status the panel polls, not swallowed.
func TestFailedRevertIsReported(t *testing.T) {
	stubRevert(t, errors.New("uci import network: boom"))
	s := &Server{}
	id, _ := s.armConfirm(map[string]string{"network": "n0"}, time.Minute)
	found, err := s.revertConfirm(id)
	if !found || err == nil {
		t.Fatalf("found=%v err=%v, want the revert error", found, err)
	}
	s.confirmMu.Lock()
	lr := s.lastRevert
	s.confirmMu.Unlock()
	if lr == nil || lr.err == nil {
		t.Fatalf("last revert not recorded as failed: %+v", lr)
	}
}

// A required config that cannot be snapshotted refuses the change; an
// optional one is skipped.
func TestSnapshotForConfirm(t *testing.T) {
	orig := snapshotFn
	t.Cleanup(func() { snapshotFn = orig })
	snapshotFn = func(c string) (string, error) {
		if c == "wireless" {
			return "", errors.New("no such config")
		}
		return c + "-data", nil
	}
	got, err := snapshotForConfirm([]string{"network"}, []string{"wireless"})
	if err != nil || !reflect.DeepEqual(got, map[string]string{"network": "network-data"}) {
		t.Fatalf("optional missing: %v %v", got, err)
	}
	if _, err := snapshotForConfirm([]string{"wireless"}, nil); err == nil {
		t.Fatal("a required config that cannot be snapshotted must refuse the change")
	}
}

// Wi-Fi is reloaded with the wifi command: OpenWrt has no init.d script
// called wireless, so the old reload restored the file and left the radios.
func TestReloadOpPerConfig(t *testing.T) {
	if op := reloadOpFor("wireless"); op.Kind != "wifi_reload" {
		t.Fatalf("wireless reload = %+v", op)
	}
	for _, c := range []string{"network", "firewall"} {
		if op := reloadOpFor(c); op.Kind != "initd" || !reflect.DeepEqual(op.Args, []string{c, "reload"}) {
			t.Fatalf("%s reload = %+v", c, op)
		}
	}
}

func TestConcurrentArmAndExpireIsSafe(t *testing.T) {
	reverted := stubRevert(t, nil)
	s := &Server{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() { s.armConfirm(map[string]string{"network": "n"}, time.Millisecond) })
	}
	wg.Wait()
	// Exactly the last window reverts; wait for it so the stub is not
	// restored while its timer still runs.
	select {
	case <-reverted:
	case <-time.After(2 * time.Second):
		t.Fatal("the pending window never reverted")
	}
	for {
		s.confirmMu.Lock()
		done := s.lastRevert != nil
		s.confirmMu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Keep or Revert sent with an absorbed window's id still reaches the joined
// window: the first tab's Keep is not refused because a second change joined.
func TestKeepWithAnAbsorbedID(t *testing.T) {
	stubRevert(t, nil)
	s := &Server{}
	firstID, _ := s.armConfirm(map[string]string{"network": "n0"}, time.Minute)
	s.armConfirm(map[string]string{"wireless": "w0"}, time.Minute)
	if !s.keepConfirm(firstID) {
		t.Fatal("Keep with the first id was refused after a second change joined")
	}
	if _, _, ok := s.confirmStatus(); ok {
		t.Fatal("the joined window is still pending after Keep")
	}
}

// A revert holds riskyMu: a risky change waits for it instead of
// snapshotting the state being reverted.
func TestRevertExcludesARiskyChange(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	orig := revertFn
	revertFn = func(map[string]string) error {
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() { revertFn = orig })

	s := &Server{}
	id, _ := s.armConfirm(map[string]string{"network": "n0"}, time.Minute)
	go func() { _, _ = s.revertConfirm(id) }()
	<-entered

	// While the revert runs, the panel reports it as running.
	s.confirmMu.Lock()
	running := s.lastRevert != nil && s.lastRevert.running
	s.confirmMu.Unlock()
	if !running {
		t.Fatal("last_revert does not say the revert is running")
	}

	got := make(chan struct{})
	go func() {
		s.riskyMu.Lock()
		close(got)
		s.riskyMu.Unlock()
	}()
	select {
	case <-got:
		t.Fatal("a risky change got in while a revert was running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the risky change never got the lock after the revert")
	}
}
