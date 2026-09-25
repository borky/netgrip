package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	pushConfigPath = "/etc/netgrip/push-config.json"
	pushTimeout    = 30 * time.Second
)

type PushConfig struct {
	ServerURL string `json:"server_url"`
	RouterID  string `json:"router_id"`
	Token     string `json:"token"`
	// FORK: ServerFP pins an https ServerURL (NETPULSE_SERVER_FP format).
	ServerFP string `json:"server_fp,omitempty"`
}

type PushResult struct {
	Ok         bool   `json:"ok"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

func GetPushConfig() PushConfig {
	data, err := os.ReadFile(pushConfigPath)
	if err != nil {
		return PushConfig{}
	}
	var cfg PushConfig
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

func SetPushConfig(cfg PushConfig) error {
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	os.MkdirAll("/etc/netgrip", 0755)
	return os.WriteFile(pushConfigPath, data, 0600)
}

func PushLatestSnapshot() PushResult {
	cfg := GetPushConfig()
	if cfg.ServerURL == "" || cfg.RouterID == "" {
		return PushResult{Error: "push not configured: set server URL and router ID first"}
	}

	snaps := ListSnapshots()
	if len(snaps) == 0 {
		return PushResult{Error: "no snapshots available"}
	}
	latest := snaps[len(snaps)-1]

	data, err := ExportSnapshot(latest.ID)
	if err != nil {
		return PushResult{Error: fmt.Sprintf("export snapshot: %s", err)}
	}

	configs := make([]string, len(uciConfigs))
	copy(configs, uciConfigs)
	configsStr := strings.Join(configs, ",")

	req, err := http.NewRequest("POST", cfg.ServerURL+"/api/config-backup", bytes.NewReader(data))
	if err != nil {
		return PushResult{Error: fmt.Sprintf("build request: %s", err)}
	}
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Router-ID", cfg.RouterID)
	req.Header.Set("X-Snapshot-ID", latest.ID)
	req.Header.Set("X-Configs", configsStr)
	req.Header.Set("X-Executor-Token", GetExecutorToken())
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	client, err := snapshotPushClient(cfg)
	if err != nil {
		return PushResult{Error: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return PushResult{Error: fmt.Sprintf("push failed: %s", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PushResult{Error: fmt.Sprintf("server returned %d", resp.StatusCode)}
	}

	return PushResult{Ok: true, SnapshotID: latest.ID}
}

// snapshotPushClient is the client for the backup push. FORK: the upload
// carries the executor token, which can change this router, so on https it
// is pinned: to the push config's own fingerprint, else to the embedded
// agent's when both address the same server. With no pin at all it checks
// the server against the system's CAs, as before - right for a server with a
// public certificate, and never an unverified connection.
func snapshotPushClient(cfg PushConfig) (*http.Client, error) {
	pins := cfg.ServerFP
	if pins == "" {
		if agent, err := ReadNetPulseConfig(prodNetPulsePaths().env); err == nil && sameNetPulseServer(agent.Server, cfg.ServerURL) {
			pins = agent.ServerFP
		}
	}
	if pins == "" || !strings.HasPrefix(cfg.ServerURL, "https://") {
		return &http.Client{
			Timeout:       pushTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}, nil
	}
	return netPulseClient(cfg.ServerURL, pins, pushTimeout)
}
