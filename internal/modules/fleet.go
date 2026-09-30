package modules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	fleetConfigPath       = "/etc/netgrip/fleet.json"
	legacyFleetConfigPath = "/etc/owpanel/fleet.json"
)

type FleetNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Password string `json:"password,omitempty"`
	// FORK: TLS is set once the node's panel was found serving HTTPS, and
	// SPKI is the key it presented then: every later request is pinned to
	// it (see fleet_tls.go).
	TLS  bool   `json:"tls,omitempty"`
	SPKI string `json:"spki,omitempty"`
}

type FleetConfig struct {
	Nodes []FleetNode `json:"nodes"`
}

type FleetNodeStatus struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Address         string `json:"address"`
	Reachable       bool   `json:"reachable"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	Error           string `json:"error,omitempty"`
	// FORK: the node's panel serves HTTPS, so "Open" links to https://.
	TLS bool `json:"tls,omitempty"`
}

type FleetStatus struct {
	Nodes []FleetNodeStatus `json:"nodes"`
}

var (
	fleetMu       sync.RWMutex
	fleetStatuses = make(map[string]FleetNodeStatus)
)

func LoadFleetConfig() (FleetConfig, error) {
	data, err := os.ReadFile(fleetConfigPath)
	if os.IsNotExist(err) && fileExists(legacyFleetConfigPath) {
		// Migrate a pre-rename fleet file if present (one shot, best effort).
		if legacy, lerr := os.ReadFile(legacyFleetConfigPath); lerr == nil {
			if merr := SaveFleetConfigFromBytes(legacy); merr == nil {
				_ = os.Remove(legacyFleetConfigPath)
			}
			data = legacy
			err = nil
		}
	}
	if err != nil {
		if os.IsNotExist(err) {
			return FleetConfig{Nodes: []FleetNode{}}, nil
		}
		return FleetConfig{}, err
	}
	var cfg FleetConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return FleetConfig{}, err
	}
	return cfg, nil
}

func SaveFleetConfig(cfg FleetConfig) error {
	if err := os.MkdirAll("/etc/netgrip", 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return SaveFleetConfigFromBytes(data)
}

// SaveFleetConfigFromBytes writes raw fleet JSON to the current path.
func SaveFleetConfigFromBytes(data []byte) error {
	return os.WriteFile(fleetConfigPath, data, 0600)
}

func AddFleetNode(node FleetNode) error {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return err
	}
	for _, n := range cfg.Nodes {
		if n.ID == node.ID {
			return fmt.Errorf("node already exists")
		}
	}
	cfg.Nodes = append(cfg.Nodes, node)
	return SaveFleetConfig(cfg)
}

func RemoveFleetNode(id string) error {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return err
	}
	var filtered []FleetNode
	for _, n := range cfg.Nodes {
		if n.ID != id {
			filtered = append(filtered, n)
		}
	}
	cfg.Nodes = filtered
	return SaveFleetConfig(cfg)
}

func ListFleet() ([]FleetNodeStatus, error) {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return nil, err
	}

	fleetMu.RLock()
	nodes := make([]FleetNodeStatus, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		status, ok := fleetStatuses[n.ID]
		if !ok {
			status = FleetNodeStatus{
				ID:      n.ID,
				Name:    n.Name,
				Address: n.Address,
			}
		}
		status.TLS = n.TLS // from the saved node, which a check may have just learned
		nodes = append(nodes, status)
	}
	fleetMu.RUnlock()

	return nodes, nil
}

func CheckFleetNode(id string) (FleetNodeStatus, error) {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return FleetNodeStatus{}, err
	}

	var node *FleetNode
	for i := range cfg.Nodes {
		if cfg.Nodes[i].ID == id {
			node = &cfg.Nodes[i]
			break
		}
	}
	if node == nil {
		return FleetNodeStatus{}, fmt.Errorf("node not found")
	}

	status, learned := checkNodeUpdateLearning(node)
	if learned {
		saveFleetNodePin(*node)
	}

	fleetMu.Lock()
	fleetStatuses[id] = status
	fleetMu.Unlock()

	return status, nil
}

func CheckAllFleet() ([]FleetNodeStatus, error) {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	results := make(chan FleetNodeStatus, len(cfg.Nodes))

	for _, node := range cfg.Nodes {
		wg.Add(1)
		go func(n FleetNode) {
			defer wg.Done()
			status, learned := checkNodeUpdateLearning(&n)
			if learned {
				saveFleetNodePin(n)
			}
			results <- status
		}(node)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	fleetMu.Lock()
	nodes := []FleetNodeStatus{}
	for status := range results {
		fleetStatuses[status.ID] = status
		nodes = append(nodes, status)
	}
	fleetMu.Unlock()

	return nodes, nil
}

func checkNodeUpdate(node FleetNode) FleetNodeStatus {
	status, _ := checkNodeUpdateLearning(&node)
	return status
}

// checkNodeUpdateLearning is checkNodeUpdate that also reports whether it
// learned the node's TLS pin on the way, filled into node. FORK.
func checkNodeUpdateLearning(node *FleetNode) (FleetNodeStatus, bool) {
	status := FleetNodeStatus{
		ID:      node.ID,
		Name:    node.Name,
		Address: node.Address,
	}

	base, client, learned, err := fleetPeerClient(node, 5*time.Second)
	if err != nil {
		status.Error = err.Error()
		return status, false
	}
	status.TLS = node.TLS
	status, ok := nodeUpdateStatus(status, node, base, client)
	return status, learned && ok
}

func nodeUpdateStatus(status FleetNodeStatus, node *FleetNode, base string, client *http.Client) (FleetNodeStatus, bool) {
	client, err := fleetPanelLogin(client, base, node.Password)
	if err != nil {
		status.Error = err.Error()
		return status, false
	}

	checkReq, _ := http.NewRequest("GET", base+"/api/selfupdate", nil)
	checkResp, err := client.Do(checkReq)
	if err != nil {
		status.Error = fmt.Sprintf("check: %v", err)
		return status, false
	}
	defer checkResp.Body.Close()

	if checkResp.StatusCode != 200 {
		status.Error = "check failed"
		return status, false
	}

	var update SelfUpdateCheck
	if err := json.NewDecoder(checkResp.Body).Decode(&update); err != nil {
		status.Error = "check decode"
		return status, false
	}

	status.Reachable = true
	status.CurrentVersion = update.Current
	status.LatestVersion = update.Latest
	status.UpdateAvailable = update.Available

	return status, true
}

func UpdateFleetNode(id string) error {
	cfg, err := LoadFleetConfig()
	if err != nil {
		return err
	}

	var node *FleetNode
	for i := range cfg.Nodes {
		if cfg.Nodes[i].ID == id {
			node = &cfg.Nodes[i]
			break
		}
	}
	if node == nil {
		return fmt.Errorf("node not found")
	}

	base, client, learned, err := fleetPeerClient(node, 10*time.Second)
	if err != nil {
		return err
	}
	if learned {
		saveFleetNodePin(*node)
	}

	client, err = fleetPanelLogin(client, base, node.Password)
	if err != nil {
		return err
	}

	updateReq, _ := http.NewRequest("POST", base+"/api/selfupdate", nil)
	updateResp, err := client.Do(updateReq)
	if err != nil {
		return fmt.Errorf("update: %v", err)
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode != 200 {
		return fmt.Errorf("update failed: HTTP %d", updateResp.StatusCode)
	}

	return nil
}
