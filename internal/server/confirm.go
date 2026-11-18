package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
	"github.com/gnacho/netgrip/internal/modules"
)

// confirmTimeout is how long a connectivity-risky apply stays pending before
// the router auto-reverts. It must stay strictly longer than the UI countdown
// so a last-second "Keep" reaches the server before the timer fires.
const confirmTimeout = 120 * time.Second

// confirmEntry is the single pending apply-rollback window. snapshots holds
// the UCI configs as they were before the first unconfirmed change, keyed by
// config name; reverting restores all of them.
type confirmEntry struct {
	id        string
	snapshots map[string]string
	expires   time.Time
	// joined holds the ids of the windows this one absorbed: a Keep or a
	// Revert sent with any of them still reaches the joined window.
	joined map[string]bool
}

// matches reports whether id names this window or one it absorbed.
func (e *confirmEntry) matches(id string) bool {
	return e != nil && (e.id == id || e.joined[id])
}

// revertResult is the outcome of the last revert, kept so the panel can
// report what actually happened rather than what was attempted.
type revertResult struct {
	at      time.Time
	err     error
	running bool
}

// revertFn restores a confirm's snapshots; a var so tests can stub it
// without a real uci binary.
var revertFn = revertSnapshots

func newConfirmID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// armConfirm registers a pending confirm and schedules its auto-revert.
//
// A change made while another is still unconfirmed joins it instead of
// replacing it: the pending snapshots, which predate both changes, win over
// the new ones for any config both touched, and the new configs are added.
// Keep then confirms both, and a timeout or a revert takes the router back to
// the state before the first unconfirmed change. Dropping the first window
// instead would keep a change nobody confirmed.
func (s *Server) armConfirm(snapshots map[string]string, timeout time.Duration) (id string, expires time.Time) {
	s.confirmMu.Lock()
	merged := make(map[string]string, len(snapshots))
	for k, v := range snapshots {
		merged[k] = v
	}
	joined := map[string]bool{}
	if s.confirm != nil {
		for k, v := range s.confirm.snapshots {
			merged[k] = v
		}
		joined[s.confirm.id] = true
		for old := range s.confirm.joined {
			joined[old] = true
		}
	}
	id = newConfirmID()
	expires = time.Now().Add(timeout)
	s.confirm = &confirmEntry{id: id, snapshots: merged, expires: expires, joined: joined}
	s.confirmMu.Unlock()

	time.AfterFunc(timeout, func() { s.expireConfirm(id) })
	return id, expires
}

// expireConfirm reverts the pending confirm when its timer fires, unless it
// was already kept/reverted (id no longer matches) in the meantime.
func (s *Server) expireConfirm(id string) {
	// Wait for a risky change in flight, but not forever: the timeout
	// revert is the safety net when the panel cannot be reached, and an
	// apply that hangs (a wifi or network reload that never returns) must
	// not hold it back. Past riskyWait it reverts without the lock.
	wait := s.riskyWait
	if wait == 0 {
		wait = defaultRiskyWait
	}
	if lockWithin(&s.riskyMu, wait) {
		defer s.riskyMu.Unlock()
	} else {
		log.Printf("[confirm] a risky change has held the lock for %s; reverting without it", wait)
	}
	s.confirmMu.Lock()
	e := s.confirm
	if e == nil || e.id != id {
		s.confirmMu.Unlock()
		return
	}
	s.confirm = nil
	s.confirmMu.Unlock()
	s.runRevert(e, "timeout")
}

// runRevert restores a confirm's snapshots, logs the outcome and records it
// for the status endpoint. A failed revert is never silent.
//
// Callers hold riskyMu, so no risky change runs while the restore does.
// The running marker is set first: the panel can tell "still reverting"
// from "nothing happened".
func (s *Server) runRevert(e *confirmEntry, why string) error {
	s.confirmMu.Lock()
	s.lastRevert = &revertResult{at: time.Now(), running: true}
	s.confirmMu.Unlock()
	// Not in the middle of an allow list or port change (their own rollback
	// would undo this revert); bounded, like riskyMu.
	if unlock, ok := modules.LockFirewallWritesWithin(defaultRiskyWait); ok {
		defer unlock()
	} else {
		log.Printf("[confirm] a firewall change has held its lock for %s; reverting without it", defaultRiskyWait)
	}
	err := revertFn(e.snapshots)
	if err != nil {
		log.Printf("[confirm] revert after %s FAILED: %v", why, err)
	} else {
		log.Printf("[confirm] reverted %v after %s", configNames(e.snapshots), why)
	}
	s.confirmMu.Lock()
	s.lastRevert = &revertResult{at: time.Now(), err: err}
	s.confirmMu.Unlock()
	return err
}

// defaultRiskyWait bounds how long a timeout revert waits for a risky
// change in flight (Server.riskyWait overrides it in tests).
const defaultRiskyWait = 30 * time.Second

// lockWithin takes mu, giving up after d.
func lockWithin(mu *sync.Mutex, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if mu.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// keepConfirm cancels the pending confirm, keeping the applied changes.
func (s *Server) keepConfirm(id string) bool {
	s.confirmMu.Lock()
	defer s.confirmMu.Unlock()
	if !s.confirm.matches(id) {
		return false
	}
	s.confirm = nil
	return true
}

// revertConfirm immediately reverts the pending confirm. found reports
// whether the id matched; err is the revert's own outcome.
func (s *Server) revertConfirm(id string) (found bool, err error) {
	s.riskyMu.Lock()
	defer s.riskyMu.Unlock()
	s.confirmMu.Lock()
	e := s.confirm
	if !e.matches(id) {
		s.confirmMu.Unlock()
		return false, nil
	}
	s.confirm = nil
	s.confirmMu.Unlock()
	return true, s.runRevert(e, "an explicit rollback")
}

// confirmStatus reports the currently pending confirm, if any.
func (s *Server) confirmStatus() (id string, expires time.Time, ok bool) {
	s.confirmMu.Lock()
	defer s.confirmMu.Unlock()
	if s.confirm == nil {
		return "", time.Time{}, false
	}
	return s.confirm.id, s.confirm.expires, true
}

// snapshotForConfirm exports the UCI configs a change can touch, before it
// is applied. A required config that cannot be exported refuses the change:
// arming a timer that has nothing to restore would report a rollback that
// cannot happen. Optional configs (wireless on a unit without radios) are
// skipped when absent.
func snapshotForConfirm(required, optional []string) (map[string]string, error) {
	out := map[string]string{}
	for _, c := range required {
		v, err := snapshotFn(c)
		if err != nil {
			return nil, fmt.Errorf("cannot take a rollback snapshot of %s, change not applied: %w", c, err)
		}
		out[c] = v
	}
	for _, c := range optional {
		if v, err := snapshotFn(c); err == nil {
			out[c] = v
		}
	}
	return out, nil
}

// snapshotFn is executor.Snapshot; a var so tests can stub it.
var snapshotFn = executor.Snapshot

// reloadOpFor is how each restored config is brought into effect on the
// running system. Wi-Fi has no init.d script on OpenWrt: it is reloaded with
// the wifi command, so an "initd wireless reload" restored the file and left
// the radios on the reverted-from settings.
func reloadOpFor(config string) executor.Op {
	switch config {
	case "wireless":
		return executor.Op{Kind: "wifi_reload", Args: []string{}}
	case "dhcp": // no init script of its own: dnsmasq reads it
		return executor.Op{Kind: "initd", Args: []string{"dnsmasq", "reload"}}
	default: // network, firewall
		return executor.Op{Kind: "initd", Args: []string{config, "reload"}}
	}
}

// revertSnapshots restores every captured config, then reloads each one. It
// keeps going past a failure so one bad config does not leave the others
// unreverted, and returns every error it met.
func revertSnapshots(snapshots map[string]string) error {
	var errs []error
	names := configNames(snapshots)
	for _, config := range names {
		if err := executor.Restore(config, snapshots[config]); err != nil {
			errs = append(errs, err)
		}
	}
	for _, config := range names {
		if err := executor.Run(reloadOpFor(config)); err != nil {
			errs = append(errs, fmt.Errorf("reload %s: %w", config, err))
		}
	}
	return errors.Join(errs...)
}

// configNames lists a snapshot's configs in a stable order (network before
// wireless before firewall would not matter to uci; stable makes logs and
// tests readable).
func configNames(snapshots map[string]string) []string {
	names := make([]string, 0, len(snapshots))
	for k := range snapshots {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// finishRiskyApply writes a module result, arming a confirm timer when the
// apply succeeded and the request asked for one. Connectivity-risky handlers
// (LAN, WAN, WiFi, firewall) route through it so their revert shares the same
// window as the LAN change (#557).
func (s *Server) finishRiskyApply(w http.ResponseWriter, probe any, rolledBack bool, err error, confirm bool, snapshots map[string]string) {
	if err != nil {
		writeModuleResult(w, probe, rolledBack, err)
		return
	}
	if confirm {
		id, expires := s.armConfirm(snapshots, confirmTimeout)
		writeJSON(w, map[string]any{
			"state":       probe,
			"rolled_back": rolledBack,
			"status":      "applied",
			"confirm":     map[string]any{"id": id, "expires": expires.Unix()},
		})
		return
	}
	writeModuleResult(w, probe, rolledBack, nil)
}

// ---- HTTP handlers ----

func (s *Server) handleConfirmStatus(w http.ResponseWriter, _ *http.Request) {
	id, expires, ok := s.confirmStatus()
	out := map[string]any{"pending": ok}
	if ok {
		out["id"] = id
		out["expires"] = expires.Unix()
	}
	s.confirmMu.Lock()
	if lr := s.lastRevert; lr != nil {
		last := map[string]any{"at": lr.at.Unix(), "ok": lr.err == nil, "running": lr.running}
		if lr.err != nil {
			last["error"] = lr.err.Error()
		}
		out["last_revert"] = last
	}
	s.confirmMu.Unlock()
	writeJSON(w, out)
}

func (s *Server) handleConfirmKeep(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeError(w, http.StatusBadRequest, "confirm id required")
		return
	}
	// The Keep request itself may ride an already-open connection, which
	// the firewall lets through whatever the change did to new ones. With
	// the quarantine enforced, refuse to keep a change that leaves the
	// panel user's device unapproved: the revert timer then undoes it.
	if err := quarantineKeepCheck(requesterIP(r)); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !s.keepConfirm(req.ID) {
		writeError(w, http.StatusNotFound, "no pending confirm")
		return
	}
	writeJSON(w, map[string]string{"status": "kept"})
}

func (s *Server) handleConfirmRevert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeError(w, http.StatusBadRequest, "confirm id required")
		return
	}
	found, err := s.revertConfirm(req.ID)
	if !found {
		writeError(w, http.StatusNotFound, "no pending confirm")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rollback failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "reverted"})
}
