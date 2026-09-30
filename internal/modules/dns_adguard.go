package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
)

// AdGuard DNS protection (#360): one toggle that hands the network DNS over
// to AdGuard Home and takes it back. Enabling points dnsmasq at the local
// AdGuard listener (127.0.0.1#<port>) with noresolv, after snapshotting the
// previous dnsmasq state to /etc/netgrip/adguard_dns_backup.json (same
// plain-file pattern as quotas.json); a failed healthcheck restores the
// snapshot and restarts dnsmasq. Disabling restores the snapshot, stops the
// adguardhome service and disables its rc.d entry, but keeps the package
// installed. The AdGuard config file is /etc/adguardhome.yaml per the init
// script's -c flag (verified on OpenWrt 24.10); when it does not exist yet
// (first launch, setup wizard pending) NetGrip writes a minimal one that
// keeps the admin UI on :3000 and moves the DNS listener to 5353 so it does
// not fight dnsmasq for :53.

const (
	adGuardBackupPath     = "/etc/netgrip/adguard_dns_backup.json"
	adGuardConfigPath     = "/etc/adguardhome.yaml"
	adGuardDefaultDNSPort = 5353
	// adGuardDefaultWebPort is AdGuard's own default for its web UI, used
	// only when neither its config nor its sockets say otherwise.
	adGuardDefaultWebPort = 3000
	adGuardProbeDomain    = "example.com"
)

// adGuardDNSBackup is the snapshot of the dnsmasq state we take over.
type adGuardDNSBackup struct {
	Version     int      `json:"version"`
	Servers     []string `json:"servers"`      // previous dhcp.@dnsmasq[0].server list
	Noresolv    string   `json:"noresolv"`     // previous value ("" when unset)
	NoresolvSet bool     `json:"noresolv_set"` // whether the option existed at all
	Port        int      `json:"port"`         // AdGuard DNS port the handoff uses
	Created     int64    `json:"created"`
}

// dnsmasqState is the slice of the dnsmasq UCI config the handoff touches.
type dnsmasqState struct {
	servers     []string
	noresolv    string
	noresolvSet bool
}

var (
	reAdGuardForwarder = regexp.MustCompile(`^127\.0\.0\.1#\d+$`)
	reUCIShowLine      = regexp.MustCompile(`^dhcp\.[A-Za-z0-9_]+\.([a-zA-Z_]+)=(.*)$`)
	reQuoted           = regexp.MustCompile(`'([^']*)'`)
)

// parseDnsmasqShow extracts server list and noresolv from the output of
// `uci show dhcp.@dnsmasq[0]`. List options print as one line with one
// quoted value per entry.
func parseDnsmasqShow(out string) dnsmasqState {
	var st dnsmasqState
	for _, line := range strings.Split(out, "\n") {
		m := reUCIShowLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "server":
			for _, q := range reQuoted.FindAllStringSubmatch(m[2], -1) {
				st.servers = append(st.servers, q[1])
			}
		case "noresolv":
			st.noresolvSet = true
			if q := reQuoted.FindStringSubmatch(m[2]); q != nil {
				st.noresolv = q[1]
			}
		}
	}
	if st.servers == nil {
		st.servers = []string{}
	}
	return st
}

func dnsmasqStateNow() dnsmasqState {
	out, err := exec.Command("uci", "show", "dhcp.@dnsmasq[0]").Output()
	if err != nil {
		return dnsmasqState{servers: []string{}}
	}
	return parseDnsmasqShow(string(out))
}

// parseAdGuardDNSPort returns dns.port from an AdGuardHome yaml config, or 0
// when absent or unparseable. Only the dns: block is scanned, so an http:
// port elsewhere never leaks in.
func parseAdGuardDNSPort(data []byte) int {
	inDNS := false
	dnsIndent := -1
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "dns:" {
			inDNS = true
			dnsIndent = indent
			continue
		}
		if !inDNS {
			continue
		}
		if indent <= dnsIndent {
			inDNS = false
			continue
		}
		if rest, ok := strings.CutPrefix(trimmed, "port:"); ok {
			if p, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil && p > 0 && p < 65536 {
				return p
			}
		}
	}
	return 0
}

// adGuardConfigFile is the AdGuard Home config the service actually uses.
// FORK: the OpenWrt package names it in UCI (adguardhome.config.config_file,
// /etc/adguardhome/adguardhome.yaml on OpenWrt 25.12); older packages pass
// /etc/adguardhome.yaml to the binary directly. Reading only the old path
// missed the whole config on current installs - DNS port, web port, DoH.
func adGuardConfigFile() string {
	if out, err := exec.Command("uci", "-q", "get", "adguardhome.config.config_file").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p
		}
	}
	return adGuardConfigPath
}

// adGuardServesDNSNow reports whether the running AdGuard Home process
// listens on :53 itself. FORK.
func adGuardServesDNSNow() bool {
	l, ok := probeAdGuardListeners()
	return ok && (l.UDP[53] || l.TCP[53])
}

// writeAdGuardConfig writes AdGuard's config so that AdGuard can still read
// it. FORK: current OpenWrt packages run AdGuard as its own user with the
// config private to it (0600), so a file root rewrote or created would lock
// it out. An existing file keeps its owner; a new one takes the owner of its
// directory, which the package creates for that user.
func writeAdGuardConfig(path string, data []byte) error {
	owner, statErr := os.Stat(path)
	if statErr != nil {
		owner, _ = os.Stat(filepath.Dir(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if owner != nil {
		if uid, gid, ok := fileOwner(owner); ok {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseAdGuardWebPort returns the port of AdGuard's web UI from its yaml
// config: http.address ("0.0.0.0:8080") on current versions, the top-level
// bind_port on older ones; 0 when neither is there. FORK.
func parseAdGuardWebPort(data []byte) int {
	inHTTP := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		top := !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")
		if top {
			inHTTP = trimmed == "http:"
			if rest, ok := strings.CutPrefix(trimmed, "bind_port:"); ok {
				if p, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil && p > 0 && p < 65536 {
					return p
				}
			}
			continue
		}
		if !inHTTP {
			continue
		}
		if rest, ok := strings.CutPrefix(trimmed, "address:"); ok {
			addr := strings.Trim(strings.TrimSpace(rest), `"'`)
			if i := strings.LastIndexByte(addr, ':'); i >= 0 {
				if p, err := strconv.Atoi(addr[i+1:]); err == nil && p > 0 && p < 65536 {
					return p
				}
			}
		}
	}
	return 0
}

// adGuardResolvedPort returns the DNS port AdGuard Home listens on: the one
// in its yaml config when present, the conventional 5353 otherwise.
func adGuardResolvedPort() int {
	if data, err := os.ReadFile(adGuardConfigFile()); err == nil {
		if p := parseAdGuardDNSPort(data); p > 0 {
			return p
		}
	}
	return adGuardDefaultDNSPort
}

func adGuardMinimalYAML(port int) string {
	return fmt.Sprintf(`http:
  address: 0.0.0.0:3000
dns:
  bind_hosts:
    - 127.0.0.1
  port: %d
`, port)
}

// planServerListOps builds the UCI ops that turn the dnsmasq server list
// from prev into next. Values are deleted before being re-added so the
// result is exact even when the two lists overlap.
func planServerListOps(prev, next []string) []executor.Op {
	var ops []executor.Op
	for _, v := range prev {
		ops = append(ops, executor.Op{Kind: "uci_del_list", Args: []string{"dhcp.@dnsmasq[0].server", v}})
	}
	for _, v := range next {
		ops = append(ops, executor.Op{Kind: "uci_add_list", Args: []string{"dhcp.@dnsmasq[0].server", v}})
	}
	return ops
}

// planNoresolvOps builds the op that restores noresolv to a previous state.
func planNoresolvOps(st dnsmasqState) []executor.Op {
	if !st.noresolvSet {
		return []executor.Op{{Kind: "uci_delete", Args: []string{"dhcp.@dnsmasq[0].noresolv"}}}
	}
	return []executor.Op{{Kind: "uci_set", Args: []string{"dhcp.@dnsmasq[0].noresolv", st.noresolv}}}
}

func adGuardForwarders(servers []string) []string {
	var out []string
	for _, s := range servers {
		if reAdGuardForwarder.MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

// adGuardProtected reports whether dnsmasq already forwards to a local
// AdGuard listener.
func adGuardProtected(st dnsmasqState) bool {
	return len(adGuardForwarders(st.servers)) > 0
}

func loadAdGuardBackup() *adGuardDNSBackup {
	data, err := os.ReadFile(adGuardBackupPath)
	if err != nil {
		return nil
	}
	var b adGuardDNSBackup
	if json.Unmarshal(data, &b) != nil || b.Version != 1 {
		return nil
	}
	return &b
}

func saveAdGuardBackup(b *adGuardDNSBackup) error {
	if err := os.MkdirAll(filepath.Dir(adGuardBackupPath), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(adGuardBackupPath, data, 0o600)
}

// dnsLookupWorks is the healthcheck: a real recursive query through the
// resolver that listens on 127.0.0.1:53 (dnsmasq), with a 5s timeout and a
// second try while dnsmasq settles after its restart.
func dnsLookupWorks() bool {
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, "nslookup", adGuardProbeDomain, "127.0.0.1").Run()
		cancel()
		if err == nil {
			return true
		}
		if i == 0 {
			time.Sleep(time.Second)
		}
	}
	return false
}

// adGuardReady polls the healthcheck until AdGuard answers through dnsmasq.
// A cold AdGuardHome start takes ~17s on a mipsle router to reach the first
// DNS answer (auth module, filters, listeners), far beyond the single
// healthcheck window; without this wait the enable rolled back exactly when
// the service was about to come up. Bounded at ~60s, then the caller rolls
// back.
func adGuardReady() bool {
	for i := 0; i < 25; i++ {
		if dnsLookupWorks() {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// adGuardApplyDNS commits a dnsmasq state and restarts the service; used for
// both the change itself and its rollback.
func adGuardApplyDNS(st dnsmasqState) error {
	cur := dnsmasqStateNow()
	ops := planServerListOps(cur.servers, st.servers)
	ops = append(ops, planNoresolvOps(st)...)
	ops = append(ops,
		executor.Op{Kind: "uci_commit", Args: []string{"dhcp"}},
		executor.Op{Kind: "initd", Args: []string{"dnsmasq", "restart"}},
	)
	return executor.Apply(ops, nil)
}

// AdGuardProtection enables or disables the full DNS handoff (#360). The
// confirm gate lives in the HTTP handler, like the banip uninstall.
func AdGuardProtection(enable bool) (*DNSConfig, bool, error) {
	if !dnsApplicable() {
		return ProbeDNS(), false, fmt.Errorf("DNS protection only applies on the gateway (dnsmasq)")
	}
	if !pkgInstalled("adguardhome") {
		return ProbeDNS(), false, fmt.Errorf("adguardhome is not installed")
	}
	st := dnsmasqStateNow()
	if enable {
		return adGuardEnable(st)
	}
	return adGuardDisable(st)
}

func adGuardEnable(st dnsmasqState) (*DNSConfig, bool, error) {
	if adGuardProtected(st) {
		return ProbeDNS(), false, fmt.Errorf("DNS protection is already active")
	}
	// FORK: AdGuard already answering :53 itself filters every client
	// already; handing dnsmasq to it on top would only add a hop.
	if adGuardServesDNSNow() {
		return ProbeDNS(), false, fmt.Errorf("AdGuard Home already answers DNS on port 53 directly; it is filtering without the handoff")
	}
	port := adGuardResolvedPort()

	// The AdGuard config may not exist yet (first launch defers to the web
	// wizard, which cannot finish because dnsmasq owns :53). Write a minimal
	// config that moves the DNS listener to the handoff port.
	wroteYAML := false
	if _, err := os.Stat(adGuardConfigFile()); os.IsNotExist(err) {
		_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"adguardhome", "stop"}})
		if err := writeAdGuardConfig(adGuardConfigFile(), []byte(adGuardMinimalYAML(port))); err != nil {
			return ProbeDNS(), false, fmt.Errorf("writing %s: %w", adGuardConfigFile(), err)
		}
		wroteYAML = true
	}

	backup := &adGuardDNSBackup{
		Version:     1,
		Servers:     st.servers,
		Noresolv:    st.noresolv,
		NoresolvSet: st.noresolvSet,
		Port:        port,
		Created:     time.Now().Unix(),
	}
	if err := saveAdGuardBackup(backup); err != nil {
		return ProbeDNS(), false, fmt.Errorf("saving dnsmasq backup: %w", err)
	}

	ops := []executor.Op{
		{Kind: "initd", Args: []string{"adguardhome", "enable"}},
		{Kind: "initd", Args: []string{"adguardhome", "start"}},
	}
	ops = append(ops, planServerListOps(st.servers, []string{fmt.Sprintf("127.0.0.1#%d", port)})...)
	ops = append(ops,
		executor.Op{Kind: "uci_set", Args: []string{"dhcp.@dnsmasq[0].noresolv", "1"}},
		executor.Op{Kind: "uci_commit", Args: []string{"dhcp"}},
		executor.Op{Kind: "initd", Args: []string{"dnsmasq", "restart"}},
	)
	if err := executor.Apply(ops, nil); err != nil {
		adGuardEnableRollback(st, wroteYAML)
		return ProbeDNS(), true, err
	}
	if !adGuardReady() {
		adGuardEnableRollback(st, wroteYAML)
		return ProbeDNS(), true, fmt.Errorf("dns healthcheck failed, restored the previous DNS config")
	}
	return ProbeDNS(), false, nil
}

// adGuardEnableRollback puts dnsmasq back to the state captured in st and,
// when NetGrip created the AdGuard config itself, removes it again so the
// router is exactly where it started.
func adGuardEnableRollback(st dnsmasqState, removeYAML bool) {
	_ = adGuardApplyDNS(st)
	if removeYAML {
		_ = os.Remove(adGuardConfigFile())
	}
	_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"adguardhome", "stop"}})
	_ = os.Remove(adGuardBackupPath)
}

func adGuardDisable(st dnsmasqState) (*DNSConfig, bool, error) {
	backup := loadAdGuardBackup()
	if backup == nil && !adGuardProtected(st) {
		return ProbeDNS(), false, fmt.Errorf("DNS protection is not active")
	}

	// Target dnsmasq state: the backup when we took one; otherwise drop only
	// the local AdGuard forwarders and the noresolv we would have set.
	target := dnsmasqState{servers: []string{}}
	if backup != nil {
		target.servers = backup.Servers
		target.noresolv = backup.Noresolv
		target.noresolvSet = backup.NoresolvSet
	} else {
		for _, s := range st.servers {
			if !reAdGuardForwarder.MatchString(s) {
				target.servers = append(target.servers, s)
			}
		}
	}

	// Restore DNS first, then take AdGuard itself out; the network keeps
	// resolving throughout.
	if err := adGuardApplyDNS(target); err != nil {
		return ProbeDNS(), true, err
	}
	ops := []executor.Op{
		{Kind: "initd", Args: []string{"adguardhome", "stop"}},
		{Kind: "initd", Args: []string{"adguardhome", "disable"}},
	}
	if err := executor.Apply(ops, nil); err != nil {
		_ = adGuardApplyDNS(st)
		return ProbeDNS(), true, err
	}
	if !dnsLookupWorks() {
		_ = adGuardApplyDNS(st)
		_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"adguardhome", "start"}})
		_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"adguardhome", "enable"}})
		return ProbeDNS(), true, fmt.Errorf("dns healthcheck failed, protection restored")
	}
	// Only drop the backup once the restore has passed the healthcheck.
	_ = os.Remove(adGuardBackupPath)
	return ProbeDNS(), false, nil
}
