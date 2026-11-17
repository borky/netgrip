package server

import (
	"net/http"

	"github.com/gnacho/netgrip/internal/modules"
)

// Router button endpoints. Saving only changes what a button press does
// later; nothing about the network changes when it is saved, so it does
// not need the confirm window.

func (s *Server) registerButtonRoutes() {
	s.mux.HandleFunc("GET /api/buttons", s.requireAuth(s.handleButtonsGet))
	s.mux.HandleFunc("POST /api/buttons", s.requireAuth(s.handleButtonsSet))
	s.mux.HandleFunc("POST /api/buttons/listen", s.requireAuth(s.handleButtonsListen))
	s.mux.HandleFunc("GET /api/buttons/last", s.requireAuth(s.handleButtonsLast))
}

func (s *Server) handleButtonsLast(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, modules.ProbeButtonsLast())
}

func (s *Server) handleButtonsGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, modules.ProbeButtons())
}

func (s *Server) handleButtonsSet(w http.ResponseWriter, r *http.Request) {
	var req modules.ButtonsConfig
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := modules.SetButtons(req)
	writeModuleResult(w, p, false, err)
}

func (s *Server) handleButtonsListen(w http.ResponseWriter, _ *http.Request) {
	p, err := modules.ListenButtons()
	writeModuleResult(w, p, false, err)
}
