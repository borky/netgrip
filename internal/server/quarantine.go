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
	s.mux.HandleFunc("POST /api/quarantine/wifi", s.requireAuth(s.handleQuarantineWifi))
}

// quarantineKeepCheck is a seam so confirm tests do not touch nft.
var quarantineKeepCheck = modules.QuarantineKeepCheck

// quarantinePendingCheck is a seam for the pending-changes refusal.
var quarantinePendingCheck = modules.QuarantinePendingCheck

// quarantineWifiTouches is a seam: does a zone change involve the Wi-Fi layer.
var quarantineWifiTouches = modules.QuarantineWifiTouches

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

// qFirewallConfigs is what a firewall-only change can alter; the Wi-Fi
// layer also creates a network with DHCP and changes SSIDs (a router
// without Wi-Fi or DHCP config cannot have the layer, so for a zone change
// those are optional).
var (
	qFirewallConfigs = []string{"firewall"}
	qWifiConfigs     = []string{"firewall", "network", "dhcp", "wireless"}
	qWifiOptional    = []string{"network", "dhcp", "wireless"}
)

// runRiskyFirewall wraps a firewall-reloading change in the confirm window.
func (s *Server) runRiskyFirewall(w http.ResponseWriter, apply func() (modules.QuarantineProbe, error)) {
	s.runRisky(w, qFirewallConfigs, nil, apply)
}

// runRisky wraps a change of configs in the confirm window.
func (s *Server) runRisky(w http.ResponseWriter, required, optional []string, apply func() (modules.QuarantineProbe, error)) {
	s.riskyMu.Lock()
	defer s.riskyMu.Unlock()
	// Before any snapshot: a snapshot (uci export) carries uncommitted
	// changes, and restoring it after a failure would commit them.
	if err := quarantinePendingCheck(required); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// An optional config with pending changes is left out of the
	// snapshots rather than refused: this change may not touch it (the
	// module refuses by itself if it would), and restoring a snapshot of it
	// would commit those changes.
	var clean []string
	for _, c := range optional {
		if quarantinePendingCheck([]string{c}) == nil {
			clean = append(clean, c)
		}
	}
	snapshots, err := snapshotForConfirm(required, clean)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	probe, err := apply()
	// Only a refusal returned as is (not wrapped) means nothing changed: a
	// wrapped one came after a step that did change something.
	_, refused := err.(*modules.QPendingError)
	if err != nil && !refused {
		// The module undoes what it can; restoring the snapshot as well
		// covers a failed undo (the configs back to before the change).
		// A refusal changed nothing, so there is nothing to restore.
		if rerr := revertFn(snapshots); rerr != nil {
			log.Printf("netgrip: quarantine: restoring the configs after a failed change: %v", rerr)
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

// handleQuarantineWifi turns the Wi-Fi layer on (a network, a firewall
// zone, the SSIDs restarted: inside the confirm window) or off (it only
// gives the SSIDs their own networks back).
func (s *Server) handleQuarantineWifi(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled          bool `json:"enabled"`
		AllowNoRequester bool `json:"allow_no_requester,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Enabled {
		s.riskyMu.Lock()
		defer s.riskyMu.Unlock()
		p, err := modules.QuarantineWifiDisable()
		writeModuleResult(w, p, false, err)
		return
	}
	ip := requesterIP(r)
	s.runRisky(w, qWifiConfigs, nil, func() (modules.QuarantineProbe, error) {
		return modules.QuarantineWifiEnable(ip, req.AllowNoRequester)
	})
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
	// With the Wi-Fi layer on, the SSIDs follow the zones.
	// With the Wi-Fi layer on, the SSIDs follow the zones: those configs
	// join the window. Otherwise they are not this change's to snapshot.
	var optional []string
	if quarantineWifiTouches() {
		optional = qWifiOptional
	}
	s.runRisky(w, qFirewallConfigs, optional, func() (modules.QuarantineProbe, error) {
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
