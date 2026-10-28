package server

import (
	"encoding/json"
	"net/http"

	"github.com/gnacho/netgrip/internal/modules"
)

func (s *Server) handleMatrixGet(w http.ResponseWriter, r *http.Request) {
	cfg := modules.LoadMatrixConfig()
	writeJSON(w, map[string]any{
		"server":   cfg.Server,
		"roomId":   cfg.RoomID,
		"tokenSet": cfg.Token != "",
		// Unreadable credentials send nothing: do not report the channel on.
		"enabled":    cfg.Enabled && !cfg.Unreadable,
		"unreadable": cfg.Unreadable,
	})
}

// handleMatrixSet: the update rules live in modules.MergeMatrixUpdate. A
// complete config is checked against the homeserver (whoami + room
// membership) before it is saved.
func (s *Server) handleMatrixSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Server  string `json:"server"`
		RoomID  string `json:"roomId"`
		Token   string `json:"token"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	cfg, validate, err := modules.MergeMatrixUpdate(modules.LoadMatrixConfig(), modules.MatrixUpdate{
		Server: body.Server, RoomID: body.RoomID, Token: body.Token, Enabled: body.Enabled,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if validate {
		if _, err := modules.ValidateMatrix(cfg); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if err := modules.SaveMatrixConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleMatrixTest(w http.ResponseWriter, r *http.Request) {
	cfg := modules.LoadMatrixConfig()
	if err := modules.SendMatrixTest(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
