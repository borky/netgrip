package modules

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gnacho/netgrip/internal/executor"
)

// AccessProbe is the read-only state of the three admin access surfaces:
// the panel itself, LuCI (uhttpd) and SSH (dropbear).
type AccessProbe struct {
	Panel PanelAccess `json:"panel"`
	LuCI  LuciAccess  `json:"luci"`
	SSH   SSHAccess   `json:"ssh"`
}

// PanelAccess covers the netgrip web server.
type PanelAccess struct {
	HTTPPort     int    `json:"http_port"`
	HTTPSEnabled bool   `json:"https_enabled"`
	ForceHTTPS   bool   `json:"force_https"`
	SessionTtl   string `json:"session_ttl"` // human string, e.g. "12h0m0s"
}

// LuciAccess covers uhttpd, which serves LuCI.
type LuciAccess struct {
	HTTPPort   int  `json:"http_port"`
	HTTPSPort  int  `json:"https_port"`
	ForceHTTPS bool `json:"force_https"`
	Enabled    bool `json:"enabled"`
}

// SSHAccess covers dropbear.
type SSHAccess struct {
	Enabled bool   `json:"enabled"`
	Port    string `json:"port"`
}

// ProbeAccess reads the current admin access state.
func ProbeAccess() *AccessProbe {
	return &AccessProbe{
		Panel: probePanelAccess(),
		LuCI:  probeLuciAccess(),
		SSH:   probeSSHAccess(),
	}
}

// panelSessionTTLMinutePath is the UCI option (in minutes) that governs how
// long a panel session token lives. Absent means the default of 12h.
const panelSessionTTLMinutePath = "netgrip.main.session_timeout"

func probePanelAccess() PanelAccess {
	p := PanelAccess{
		HTTPPort:   8080,
		SessionTtl: PanelSessionTTLString(),
	}
	if p.HTTPSEnabled = uciGet("netgrip.main.https") == "1"; p.HTTPSEnabled {
		p.ForceHTTPS = uciGet("netgrip.main.force_https") == "1"
	}
	if v, err := strconv.Atoi(uciGet("netgrip.main.http_port")); err == nil && v > 0 {
		p.HTTPPort = v
	}
	return p
}

// PanelSessionTTLMinutes returns the configured panel session timeout in
// minutes, or 720 (12h) when unset or invalid.
func PanelSessionTTLMinutes() int {
	if v, err := strconv.Atoi(uciGet(panelSessionTTLMinutePath)); err == nil && v > 0 {
		return v
	}
	return 12 * 60
}

// PanelSessionTTLString returns a human-readable session TTL, e.g. "12h0m0s".
func PanelSessionTTLString() string {
	return (time.Duration(PanelSessionTTLMinutes()) * time.Minute).String()
}

// SetPanelSessionTTL persists the panel session timeout (minutes).
// It only affects tokens issued afterwards; existing tokens keep their
// original expiry.
func SetPanelSessionTTL(minutes int) error {
	if minutes <= 0 {
		return fmt.Errorf("session timeout must be > 0 minutes")
	}
	if !uciSectionExists("netgrip.main") {
		// The netgrip UCI package may not exist yet (panel never wrote the
		// section). `uci import` creates the config package with a NAMED
		// section so `uci set netgrip.main.<opt>=<val>` resolves. A bare
		// `config main` would create an anonymous @main[0], which `uci set`
		// cannot address by name.
		cmd := exec.Command("uci", "import", "netgrip")
		cmd.Stdin = strings.NewReader("config panel 'main'\n\toption panel 'panel'\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("init netgrip config: %s", strings.TrimSpace(string(out)))
		}
	}
	ops := []executor.Op{
		{Kind: "uci_set", Args: []string{panelSessionTTLMinutePath, strconv.Itoa(minutes)}},
		{Kind: "uci_commit", Args: []string{"netgrip"}},
	}
	return executor.Apply(ops, nil)
}

func probeLuciAccess() LuciAccess {
	l := LuciAccess{Enabled: executor.ServiceEnabled("uhttpd")}
	l.HTTPPort = parseListenPort(uciGet("uhttpd.main.listen_http"))
	if l.HTTPPort == 0 {
		l.HTTPPort = 80
	}
	l.HTTPSPort = parseListenPort(uciGet("uhttpd.main.listen_https"))
	if l.HTTPSPort == 0 {
		l.HTTPSPort = 443
	}
	l.ForceHTTPS = uciGet("uhttpd.main.redirect_https") == "1"
	return l
}

func probeSSHAccess() SSHAccess {
	return SSHAccess{
		Enabled: executor.ServiceEnabled("dropbear"),
		Port:    uciGet("dropbear.main.Port"),
	}
}

// parseListenPort extracts the port from a uhttpd listen_* value such as
// "0.0.0.0:80 [::]:80". Returns 0 when not parseable.
func parseListenPort(v string) int {
	for _, token := range strings.Fields(v) {
		idx := strings.LastIndex(token, ":")
		if idx < 0 {
			continue
		}
		if port, err := strconv.Atoi(token[idx+1:]); err == nil {
			return port
		}
	}
	return 0
}

// SetLuciAccess applies uhttpd HTTP/HTTPS ports and redirect_https.
func SetLuciAccess(cfg LuciAccess) (*AccessProbe, bool, error) {
	if !executor.ServiceEnabled("uhttpd") {
		if err := executor.Run(executor.Op{Kind: "initd", Args: []string{"uhttpd", "enable"}}); err != nil {
			return ProbeAccess(), false, fmt.Errorf("uhttpd service missing: %w", err)
		}
	}
	snap, err := executor.Snapshot("uhttpd")
	if err != nil {
		return ProbeAccess(), false, fmt.Errorf("snapshot uhttpd: %w", err)
	}
	rollback := func() {
		_ = executor.Restore("uhttpd", snap)
		_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"uhttpd", "restart"}})
	}

	if err := executor.Apply(luciOps(cfg), nil); err != nil {
		rollback()
		return ProbeAccess(), true, err
	}
	_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"uhttpd", "restart"}})

	if !luciHealth(cfg) {
		rollback()
		return ProbeAccess(), true, fmt.Errorf("uhttpd healthcheck failed, rolled back")
	}
	return ProbeAccess(), false, nil
}

func luciOps(cfg LuciAccess) []executor.Op {
	var ops []executor.Op
	set := func(key, value string) {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{key, value}})
	}
	if cfg.HTTPPort > 0 && cfg.HTTPPort <= 65535 {
		set("uhttpd.main.listen_http", fmt.Sprintf("0.0.0.0:%d [::]:%d", cfg.HTTPPort, cfg.HTTPPort))
	} else {
		set("uhttpd.main.listen_http", "")
	}
	if cfg.HTTPSPort > 0 && cfg.HTTPSPort <= 65535 {
		set("uhttpd.main.listen_https", fmt.Sprintf("0.0.0.0:%d [::]:%d", cfg.HTTPSPort, cfg.HTTPSPort))
	} else {
		set("uhttpd.main.listen_https", "")
	}
	redirect := "0"
	if cfg.ForceHTTPS {
		redirect = "1"
	}
	set("uhttpd.main.redirect_https", redirect)
	ops = append(ops, executor.Op{Kind: "uci_commit", Args: []string{"uhttpd"}})
	return ops
}

func luciHealth(cfg LuciAccess) bool {
	// The question is whether uhttpd came back after the restart, not
	// whether its certificate is trustworthy. Routers ship a self-signed
	// one - CN=OpenWrt, no IP SAN - so a verifying client fails the
	// handshake against loopback every time, and turning "force HTTPS" on
	// could never succeed: the check rolled back a change that had worked.
	// Skipping verification is safe here in a way it would not be anywhere
	// else: the request never leaves the box.
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	scheme := "http"
	port := cfg.HTTPPort
	if cfg.ForceHTTPS {
		scheme = "https"
		port = cfg.HTTPSPort
		if port <= 0 {
			port = 443
		}
	} else if port <= 0 {
		port = 80
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d/", scheme, port)
	for i := 0; i < 10; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// SetSSHAccess applies dropbear enable + port.
func SetSSHAccess(cfg SSHAccess) (*AccessProbe, bool, error) {
	snap, err := executor.Snapshot("dropbear")
	if err != nil {
		return ProbeAccess(), false, fmt.Errorf("snapshot dropbear: %w", err)
	}
	rollback := func() {
		_ = executor.Restore("dropbear", snap)
		_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"dropbear", "restart"}})
	}

	if err := executor.Apply(sshOps(cfg), nil); err != nil {
		rollback()
		return ProbeAccess(), true, err
	}
	_ = executor.Run(executor.Op{Kind: "initd", Args: []string{"dropbear", "restart"}})

	probe := ProbeAccess()
	if !sshHealthy(cfg) {
		rollback()
		return ProbeAccess(), true, fmt.Errorf("dropbear healthcheck failed, rolled back")
	}
	return probe, false, nil
}

func sshOps(cfg SSHAccess) []executor.Op {
	var ops []executor.Op
	set := func(key, value string) {
		ops = append(ops, executor.Op{Kind: "uci_set", Args: []string{key, value}})
	}
	if cfg.Enabled {
		set("dropbear.main.enable", "1")
	} else {
		set("dropbear.main.enable", "0")
	}
	if cfg.Port != "" {
		port, perr := strconv.Atoi(cfg.Port)
		if perr != nil || port < 1 || port > 65535 {
			port = 22
		}
		set("dropbear.main.Port", strconv.Itoa(port))
	}
	if cfg.Enabled {
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"dropbear", "enable"}})
	} else {
		ops = append(ops, executor.Op{Kind: "initd", Args: []string{"dropbear", "disable"}})
	}
	ops = append(ops,
		executor.Op{Kind: "uci_commit", Args: []string{"dropbear"}},
		executor.Op{Kind: "initd", Args: []string{"dropbear", "restart"}},
	)
	return ops
}

func sshHealthy(cfg SSHAccess) bool {
	if !executor.ServiceRunning("dropbear") {
		return false
	}
	if !cfg.Enabled {
		return executor.ServiceEnabled("dropbear") == cfg.Enabled
	}
	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		port = 22
	}
	return listeningOnPort(port)
}

// listeningOnPort reports whether anything holds a listening socket on the
// port, on any address.
//
// Dialling 127.0.0.1 answers a different question. dropbear bound to one
// interface - `option Interface 'lan'`, which is how you keep SSH off the
// WAN - never listens on loopback, so the dial is refused and a perfectly
// healthy daemon looks dead. The healthcheck then rolls back a change that
// was fine, and says SSH is broken when it is not.
//
// Reading /proc is also cheaper than a dial with a timeout, on a path that
// runs while the user waits for a save to come back.
func listeningOnPort(port int) bool {
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if hasListenerOnPort(string(b), port) {
			return true
		}
	}
	return false
}

// hasListenerOnPort parses one /proc/net/tcp table: the local address column
// is HEX_ADDRESS:HEX_PORT and state 0A is TCP_LISTEN. Split out so the
// parsing is testable against captured router output.
func hasListenerOnPort(table string, port int) bool {
	lines := strings.Split(table, "\n")
	if len(lines) < 2 {
		return false
	}
	for _, line := range lines[1:] { // the first line is the header
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		colon := strings.LastIndex(f[1], ":")
		if colon < 0 {
			continue
		}
		p, err := strconv.ParseInt(f[1][colon+1:], 16, 32)
		if err == nil && int(p) == port {
			return true
		}
	}
	return false
}

const sslDir = "/etc/netgrip/ssl"

// Variables y no constantes para que los tests puedan apuntarlas a un
// directorio temporal; en ejecución nadie las cambia.
var (
	certPath = sslDir + "/cert.pem"
	keyPath  = sslDir + "/key.pem"

	// El par de uhttpd, el que sirve LuCI.
	routerCertPath = "/etc/uhttpd.crt"
	routerKeyPath  = "/etc/uhttpd.key"
)

func fileReadable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// HasRouterCert dice si el par de uhttpd está disponible para elegirlo.
func HasRouterCert() bool {
	return fileReadable(routerCertPath) && fileReadable(routerKeyPath)
}

// CertSource dice qué par se usaría: el configurado si lo hay y, si no está
// configurado, el que el arranque elegiría por descarte.
//
// Sin esto el selector enseñaba "el propio del panel" siempre que la
// configuración estuviera vacía, aunque no existiera tal par y lo que se
// estuviera sirviendo fuese el del router. Un selector que nombra algo
// distinto de lo que hay es peor que no tenerlo: invita a guardar creyendo
// que no se cambia nada.
func CertSource() string {
	switch c, _ := HTTPSCertPaths(); c {
	case routerCertPath:
		return CertSourceRouter
	case certPath:
		return CertSourcePanel
	}
	// Sin configurar: el mismo orden que sigue el arranque.
	if HasSelfSignedCert() {
		return CertSourcePanel
	}
	if HasRouterCert() {
		return CertSourceRouter
	}
	// Ninguno existe todavía: el propio es el que se generaría.
	return CertSourcePanel
}

func HasSelfSignedCert() bool {
	_, err1 := os.Stat(certPath)
	_, err2 := os.Stat(keyPath)
	return err1 == nil && err2 == nil
}

func GenerateSelfSignedCert() error {
	if err := os.MkdirAll(sslDir, 0700); err != nil {
		return fmt.Errorf("mkdir ssl: %w", err)
	}
	hostname, _ := os.Hostname()
	certPEM, keyPEM, err := buildSelfSigned(hostname, localAddresses(), time.Now())
	if err != nil {
		return err
	}
	return writeSelfSigned(certPath, keyPath, certPEM, keyPEM)
}

func HTTPSCertPaths() (string, string) {
	return uciGet("netgrip.main.https_cert"), uciGet("netgrip.main.https_key")
}

// DisableHTTPS devuelve el panel a HTTP. No borra el certificado: volver a
// activarlo no tiene por qué regenerarlo, y un par generado a mano o puesto
// por el usuario no es nuestro para tirarlo.
func DisableHTTPS() error {
	if !uciSectionExists("netgrip.main") {
		return nil // nunca se activó: nada que apagar
	}
	return executor.Apply([]executor.Op{
		{Kind: "uci_set", Args: []string{"netgrip.main.https", "0"}},
		{Kind: "uci_commit", Args: []string{"netgrip"}},
	}, nil)
}

// HTTPSEnabled dice si el panel está configurado para servir TLS. Es lo que
// está en la configuración, no cómo se arrancó el proceso: entre cambiarlo y
// reiniciar, los dos difieren.
func HTTPSEnabled() bool {
	return uciGet("netgrip.main.https") == "1"
}

// Certificate sources the panel can serve. Named rather than inferred: the
// fallback order used to decide it silently, so clearing the configured
// paths still served the panel's own pair because the files were on disk,
// which is not what "use the router's certificate" means to anybody.
const (
	CertSourcePanel  = "panel"  // el par propio del panel, con las IPs en el SAN
	CertSourceRouter = "router" // el de uhttpd, el mismo que sirve LuCI
)

// EnableHTTPS turns the panel's TLS on with the chosen certificate, writing
// the paths explicitly so what is served is what was asked for.
func EnableHTTPS(source string) error {
	certFile, keyFile := certPath, keyPath
	if source == CertSourceRouter {
		certFile, keyFile = routerCertPath, routerKeyPath
		if !fileReadable(certFile) || !fileReadable(keyFile) {
			return fmt.Errorf("the router's certificate is not at %s and %s", certFile, keyFile)
		}
	} else if !HasSelfSignedCert() {
		if err := GenerateSelfSignedCert(); err != nil {
			return err
		}
	}
	if !uciSectionExists("netgrip.main") {
		cmd := exec.Command("uci", "import", "netgrip")
		cmd.Stdin = strings.NewReader("config panel 'main'\n\toption panel 'panel'\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("init netgrip config: %s", strings.TrimSpace(string(out)))
		}
	}
	ops := []executor.Op{
		{Kind: "uci_set", Args: []string{"netgrip.main.https", "1"}},
		{Kind: "uci_set", Args: []string{"netgrip.main.https_cert", certFile}},
		{Kind: "uci_set", Args: []string{"netgrip.main.https_key", keyFile}},
		{Kind: "uci_commit", Args: []string{"netgrip"}},
	}
	return executor.Apply(ops, nil)
}
