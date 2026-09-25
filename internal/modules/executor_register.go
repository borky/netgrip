package modules

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// registerExecutorToken comparte el token del executor con NetPulse (#411):
// lo necesita para delegar ops (p. ej. la propagación de MQTT) sin depender
// de que el router haya subido un backup de configuración antes. Fail-silent:
// si el servidor no está, el agente lo reintenta en su próximo arranque.
//
// FORK: pinned like the embedded agent (serverFP), so on https the token goes
// only to the server the agent trusts.
func registerExecutorToken(server, serverFP, slug, agentToken string) {
	body, err := json.Marshal(map[string]string{"token": GetExecutorToken()})
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST",
		strings.TrimRight(server, "/")+"/api/agents/executor-token", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("X-Router-ID", slug)
	client, err := netPulseClient(server, serverFP, 10*time.Second)
	if err != nil {
		log.Printf("netpulse: no se pudo registrar el executor token: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("netpulse: no se pudo registrar el executor token: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("netpulse: registro del executor token respondió %d", resp.StatusCode)
	}
}
