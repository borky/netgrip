package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/gnacho/netgrip/internal/modules"
)

// Device quarantine endpoints. Turning the feature on and changing the
// protected zones reload the firewall, so they run inside the confirm
// window like the other connectivity-risky changes: if the panel cannot
// confirm in time, the firewall config is restored. Everything else only
// grants access, changes what unapproved devices get, or removes rules,
// none of which can cut off an approved device.

func (s *Server) registerQuarantineRoutes() {
	s.mux.HandleFunc("GET /api/quarantine", s.requireAuth(s.handleQuarantineGet))
	s.mux.HandleFunc("GET /api/quarantine/candidates", s.requireAuth(s.handleQuarantineCandidates))
	s.mux.HandleFunc("POST /api/quarantine/enable", s.requireAuth(s.handleQuarantineEnable))
	s.mux.HandleFunc("POST /api/quarantine/disable", s.requireAuth(s.handleQuarantineDisable))
	s.mux.HandleFunc("POST /api/quarantine/zones", s.requireAuth(s.handleQuarantineZones))
	s.mux.HandleFunc("POST /api/quarantine/mode", s.requireAuth(s.handleQuarantineMode))
	s.mux.HandleFunc("POST /api/quarantine/approve", s.requireAuth(s.handleQuarantineApprove))
	s.mux.HandleFunc("POST /api/quarantine/revoke", s.requireAuth(s.handleQuarantineRevoke))
	s.mux.HandleFunc("POST /api/quarantine/forget", s.requireAuth(s.handleQuarantineForget))
	s.mux.HandleFunc("POST /api/quarantine/pause", s.requireAuth(s.handleQuarantinePause))
	s.mux.HandleFunc("POST /api/quarantine/resume", s.requireAuth(s.handleQuarantineResume))
}

// quarantineKeepCheck is a seam so confirm tests do not touch nft.
var quarantineKeepCheck = modules.QuarantineKeepCheck

// requesterIP is the panel user's address, IPv4 or IPv6.
func requesterIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func (s *Server) handleQuarantineGet(w http.ResponseWriter, r *http.Request) {
	p := modules.ProbeQuarantine()
	writeJSON(w, map[string]any{"state": p, "you": modules.QuarantineRequesterMAC(requesterIP(r))})
}

func (s *Server) handleQuarantineCandidates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"candidates": modules.QuarantineCandidates(requesterIP(r))})
}

// runRiskyFirewall wraps a firewall-reloading change in the confirm window.
func (s *Server) runRiskyFirewall(w http.ResponseWriter, apply func() (modules.QuarantineProbe, error)) {
	s.riskyMu.Lock()
	defer s.riskyMu.Unlock()
	snapshots, err := snapshotForConfirm([]string{"firewall"}, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	probe, err := apply()
	if err != nil {
		// The module undoes what it can; restoring the snapshot as well
		// covers a failed undo (the firewall back to before the change).
		if rerr := revertFn(snapshots); rerr != nil {
			log.Printf("netgrip: quarantine: restoring the firewall after a failed change: %v", rerr)
		}
		probe = modules.ProbeQuarantine()
	}
	s.finishRiskyApply(w, probe, false, err, true, snapshots)
}

func (s *Server) handleQuarantineEnable(w http.ResponseWriter, r *http.Request) {
	var req modules.QEnableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := requesterIP(r)
	s.runRiskyFirewall(w, func() (modules.QuarantineProbe, error) { return modules.QuarantineEnable(req, ip) })
}

func (s *Server) handleQuarantineZones(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Zones            []string `json:"zones"`
		AllowNoRequester bool     `json:"allow_no_requester,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := requesterIP(r)
	s.runRiskyFirewall(w, func() (modules.QuarantineProbe, error) {
		return modules.QuarantineSetZones(req.Zones, ip, req.AllowNoRequester)
	})
}

// handleQuarantineDisable reloads the firewall too: it is serialized with
// the confirm-window changes so it cannot interleave with a revert.
func (s *Server) handleQuarantineDisable(w http.ResponseWriter, _ *http.Request) {
	s.riskyMu.Lock()
	defer s.riskyMu.Unlock()
	p, err := modules.QuarantineDisable()
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantineMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.QuarantineSetMode(req.Mode)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantineApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Devices []modules.QApproveItem `json:"devices"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.QuarantineApprove(req.Devices)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantineRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC   string `json:"mac"`
		Force bool   `json:"force,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.QuarantineRevoke(req.MAC, requesterIP(r), req.Force)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantineForget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC string `json:"mac"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.QuarantineForget(req.MAC)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantinePause(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Minutes int    `json:"minutes"`
		Kind    string `json:"kind"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.QuarantinePause(req.Minutes, req.Kind)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleQuarantineResume(w http.ResponseWriter, r *http.Request) {
	p, err := modules.QuarantineResume(requesterIP(r))
	writeModuleResult(w, p, false, err)
}
