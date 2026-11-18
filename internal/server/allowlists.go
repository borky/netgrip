package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gnacho/netgrip/internal/modules"
)

// Allow lists (see modules/allowlists.go).

// writeAllowResult answers an allow list change. A change that needs the
// user's confirmation answers 409 with needs_force and the reason.
func writeAllowResult(w http.ResponseWriter, probe *modules.AllowProbe, rolledBack bool, err error) {
	var nf *modules.AllowNeedsForce
	if errors.As(err, &nf) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "needs_force", "needs_force": true, "error": nf.Reason, "state": probe})
		return
	}
	writeModuleResult(w, probe, rolledBack, err)
}

func (s *Server) handleAllowGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, modules.ProbeAllowlists(requesterIP(r)))
}

func (s *Server) handleAllowSave(w http.ResponseWriter, r *http.Request) {
	var req modules.AllowSaveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	probe, err := modules.AllowSave(req, requesterIP(r))
	writeAllowResult(w, probe, false, err)
}

func (s *Server) handleAllowDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	probe, rb, err := modules.AllowDelete(req.ID, requesterIP(r))
	writeAllowResult(w, probe, rb, err)
}

// handleAllowUse ties a port to a list (or opens it to anyone). From
// outside the router's own networks the change arms the revert timer: if
// it cuts the requester off, the router puts the firewall back by itself.
func (s *Server) handleAllowUse(w http.ResponseWriter, r *http.Request) {
	var req modules.AllowUseRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := requesterIP(r)
	confirm := req.List != "" && !modules.AllowRequesterLocal(ip)
	s.riskyMu.Lock()
	defer s.riskyMu.Unlock()
	var snapshots map[string]string
	if confirm {
		var err error
		if snapshots, err = snapshotForConfirm([]string{"firewall"}, nil); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	probe, rb, err := modules.AllowUse(req, ip)
	var nf *modules.AllowNeedsForce
	if errors.As(err, &nf) {
		writeAllowResult(w, probe, rb, err)
		return
	}
	s.finishRiskyApply(w, probe, rb, err, confirm, snapshots)
}

func (s *Server) handleAllowTakeoverInfo(w http.ResponseWriter, r *http.Request) {
	info, err := modules.AllowTakeoverInfo(r.URL.Query().Get("set"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, info)
}

func (s *Server) handleAllowTakeover(w http.ResponseWriter, r *http.Request) {
	var req modules.AllowTakeoverRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	probe, rb, err := modules.AllowTakeover(req, requesterIP(r))
	writeAllowResult(w, probe, rb, err)
}
