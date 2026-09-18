package modules

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/gnacho/netgrip/internal/executor"
)

type NlbwmonProbe struct {
	Installed        bool `json:"installed"`
	Running          bool `json:"running"`
	Generations      int  `json:"generations"`
	CommitInterval   int  `json:"commit_interval"`
	PreallocDays     int  `json:"prealloc_days"`
	ProtocolDatabase bool `json:"protocol_database"`
}

func ProbeNlbwmon() *NlbwmonProbe {
	p := &NlbwmonProbe{
		Installed: executor.ServiceEnabled("nlbwmon") || exec.Command("which", "nlbwmon").Run() == nil,
		Running:   executor.ServiceRunning("nlbwmon"),
	}
	if !p.Installed {
		return p
	}
	if v, err := strconv.Atoi(uciGet("nlbwmon.core.database_generations")); err == nil {
		p.Generations = v
	}
	if v, err := strconv.Atoi(uciGet("nlbwmon.core.commit_interval")); err == nil {
		p.CommitInterval = v
	}
	if v, err := strconv.Atoi(uciGet("nlbwmon.core.database_prealloc_days")); err == nil {
		p.PreallocDays = v
	}
	p.ProtocolDatabase = uciGet("nlbwmon.core.protocol_database") == "1"
	return p
}

type NlbwmonConfig struct {
	Enabled        *bool `json:"enabled,omitempty"`
	Generations    *int  `json:"generations,omitempty"`
	CommitInterval *int  `json:"commit_interval,omitempty"`
	PreallocDays   *int  `json:"prealloc_days,omitempty"`
}

func SetNlbwmon(cfg NlbwmonConfig) (*NlbwmonProbe, bool, error) {
	freshInstall := false
	if !ProbeNlbwmon().Installed {
		if cfg.Enabled == nil || !*cfg.Enabled {
			return nil, false, fmt.Errorf("nlbwmon is not installed")
		}
		if err := executor.Run(executor.Op{Kind: "pkg_add", Args: []string{"nlbwmon"}}); err != nil {
			return nil, false, fmt.Errorf("install nlbwmon: %w", err)
		}
		freshInstall = true
	}
	snap, err := executor.Snapshot("nlbwmon")
	if err != nil {
		return nil, false, fmt.Errorf("snapshot nlbwmon: %w", err)
	}

	var ops []executor.Op
	if cfg.Enabled != nil {
		action := "enable"
		if !*cfg.Enabled {
			action = "disable"
		}
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"nlbwmon", action}})
		if freshInstall && *cfg.Enabled {
			ops = append(ops, executor.Op{Kind: "initd", Args: []string{"nlbwmon", "start"}})
		}
	}
	if cfg.Generations != nil {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{"nlbwmon.core.database_generations", strconv.Itoa(*cfg.Generations)}})
	}
	if cfg.CommitInterval != nil {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{"nlbwmon.core.commit_interval", strconv.Itoa(*cfg.CommitInterval)}})
	}
	if cfg.PreallocDays != nil {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{"nlbwmon.core.database_prealloc_days", strconv.Itoa(*cfg.PreallocDays)}})
	}

	if len(ops) > 0 {
		hasUciSet := false
		for _, op := range ops {
			if op.Kind == "uci_set" {
				hasUciSet = true
				break
			}
		}
		if hasUciSet {
			ops = append(ops, executor.Op{Kind: "uci_commit", Args: []string{"nlbwmon"}})
			ops = append(ops, executor.Op{Kind: "initd", Args: []string{"nlbwmon", "restart"}})
		}
	}

	if err := executor.Apply(ops, nil); err != nil {
		_ = executor.Restore("nlbwmon", snap)
		executor.Run(executor.Op{Kind: "initd", Args: []string{"nlbwmon", "restart"}})
		return ProbeNlbwmon(), true, err
	}
	return ProbeNlbwmon(), false, nil
}

func NlbwmonTopHosts(n int) string {
	out, err := exec.Command("nlbw", "-c", "show", "-g", "local_addr", "-o", "total_bytes", "-l", strconv.Itoa(n)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// Per-device and per-protocol accounting from nlbwmon.
//
// The router has no other source of per-device traffic: the Rx/Tx counters
// in Client come from the wireless station dump, so they exist only for
// stations associated to THIS router. Anything wired, or behind a switch or
// another access point, has none — on a gateway whose clients all live
// behind a switch, that list is always empty.
//
// nlbwmon accounts every conntrack flow it sees and groups it by MAC, so it
// covers all of them. It is read read-only, through `nlbw`.
// ---------------------------------------------------------------------------

// NlbwUsage is one accounted row: a device, or a protocol.
//
// Down/Up are from the DEVICE's point of view. Note this is the opposite of
// Client.RxBytes, where Rx is what the AP received (the client's upload);
// nlbwmon's rx_bytes is what the host downloaded.
type NlbwUsage struct {
	// Key identifies the row: a MAC for a device, a protocol name for an
	// app ("HTTPS", "QUIC", "DNS"…).
	Key string `json:"key"`
	// IP of the device, when the row is a device and nlbwmon knows one.
	IP string `json:"ip,omitempty"`
	// Conns is the number of accounted connections.
	Conns int64 `json:"conns"`
	// DownBytes/UpBytes as the device sees them.
	DownBytes int64 `json:"down_bytes"`
	UpBytes   int64 `json:"up_bytes"`
}

// nlbwQuery runs nlbw and returns its rows keyed by column name.
//
// The JSON output carries its own column list, so columns are looked up by
// name rather than by position: the order differs between groupings, and a
// future nlbwmon is free to add one.
func nlbwQuery(group string) ([]map[string]any, error) {
	out, err := exec.Command("nlbw", "-c", "json", "-g", group).Output()
	if err != nil {
		return nil, err
	}
	return nlbwParse(out)
}

// nlbwParse turns nlbw's {columns, data} document into rows keyed by column
// name. Split from the command so it can be tested without nlbwmon.
func nlbwParse(out []byte) ([]map[string]any, error) {
	var doc struct {
		Columns []string `json:"columns"`
		Data    [][]any  `json:"data"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(doc.Data))
	for _, raw := range doc.Data {
		row := map[string]any{}
		for i, col := range doc.Columns {
			if i < len(raw) {
				row[col] = raw[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// deviceKey: a row belongs to the device identified by its MAC. The null
// MAC is traffic nlbwmon could not attribute, and is not a device.
func deviceKey(r map[string]any) (string, string) {
	mac := strings.ToLower(nlbwStr(r, "mac"))
	if mac == "00:00:00:00:00:00" {
		return "", ""
	}
	return mac, nlbwStr(r, "ip")
}

// appKey: a row belongs to the protocol nlbwmon named it, or "other".
func appKey(r map[string]any) (string, string) {
	if name := nlbwStr(r, "layer7"); name != "" {
		return name, ""
	}
	return "other", ""
}

func nlbwInt(row map[string]any, col string) int64 {
	if f, ok := row[col].(float64); ok {
		return int64(f)
	}
	return 0
}

func nlbwStr(row map[string]any, col string) string {
	if s, ok := row[col].(string); ok {
		return s
	}
	return ""
}

// nlbwAggregate folds rows into totals per key, preserving first-seen order
// so the result is stable before sorting.
func nlbwAggregate(rows []map[string]any, keyOf func(map[string]any) (string, string)) []NlbwUsage {
	byKey := map[string]*NlbwUsage{}
	order := []string{}
	for _, r := range rows {
		key, ip := keyOf(r)
		if key == "" {
			continue
		}
		u, ok := byKey[key]
		if !ok {
			u = &NlbwUsage{Key: key}
			byKey[key] = u
			order = append(order, key)
		}
		// nlbw emits several rows per key and not all carry an address:
		// keep the first non-empty one, or the row stays unlabelled.
		if u.IP == "" {
			u.IP = ip
		}
		u.Conns += nlbwInt(r, "conns")
		u.DownBytes += nlbwInt(r, "rx_bytes")
		u.UpBytes += nlbwInt(r, "tx_bytes")
	}
	out := make([]NlbwUsage, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// nlbwTop sorts by total traffic and keeps the first n (n <= 0 = all).
func nlbwTop(rows []NlbwUsage, n int) []NlbwUsage {
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].DownBytes+rows[i].UpBytes > rows[j].DownBytes+rows[j].UpBytes
	})
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	if rows == nil {
		return []NlbwUsage{}
	}
	return rows
}

// NlbwmonTopDevices returns the n devices that moved the most traffic.
// Empty when nlbwmon is not installed or has nothing yet, which the caller
// treats as "no data" rather than as an error.
func NlbwmonTopDevices(n int) []NlbwUsage {
	rows, err := nlbwQuery("mac,ip")
	if err != nil {
		return []NlbwUsage{}
	}
	return nlbwTop(nlbwAggregate(rows, deviceKey), n)
}

// NlbwmonTopApps returns the n protocols that moved the most traffic.
// nlbwmon names them from its protocol database (HTTPS, QUIC, DNS…), which
// is coarser than real DPI but needs no extra daemon and, unlike grouping
// conntrack by port, says something a person recognises. What it cannot
// name comes back as "other" instead of a port number.
func NlbwmonTopApps(n int) []NlbwUsage {
	rows, err := nlbwQuery("layer7")
	if err != nil {
		return []NlbwUsage{}
	}
	return nlbwTop(nlbwAggregate(rows, appKey), n)
}
