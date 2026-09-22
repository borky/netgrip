package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gnacho/netgrip/internal/auth"
	"github.com/gnacho/netgrip/internal/modules"
	"github.com/gnacho/netgrip/internal/server"
)

var version = "dev"

func main() {
	listen := flag.String("listen", "0.0.0.0", "listen address")
	showVersion := flag.Bool("version", false, "print version and exit")
	port := flag.Int("port", 8090, "listen port")
	rpcdURL := flag.String("rpcd-url", auth.DefaultRPCdURL, "rpcd JSON-RPC endpoint used for login validation")
	updateRepo := flag.String("update-repo", "", "GitHub owner/name to check for releases (default: upstream; env NETGRIP_UPDATE_REPO)")
	useTLS := flag.Bool("https", false, "serve the panel over HTTPS on the listen port")
	tlsCert := flag.String("https-cert", "", "certificate to serve with -https (default: the panel's own, else uhttpd's)")
	tlsKey := flag.String("https-key", "", "private key to serve with -https (default: the panel's own, else uhttpd's)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	// Where this build looks for its own updates. A binary that is not
	// upstream's must not offer to replace itself with upstream's asset, which
	// would silently undo whatever it added. The flag wins over the
	// environment so a service file can set one and an operator override it.
	repo := *updateRepo
	if repo == "" {
		repo = os.Getenv("NETGRIP_UPDATE_REPO")
	}
	if repo != "" {
		modules.SetUpdateRepo(repo)
	}

	// The flag always has a value (its default), so only treat it as an
	// explicit override when it differs from the default endpoint.
	explicit := ""
	if *rpcdURL != auth.DefaultRPCdURL {
		explicit = *rpcdURL
	}
	resolvedRPCd := auth.DetectRPCdEndpoint(explicit)
	if resolvedRPCd == "" {
		log.Printf("no rpcd endpoint answered among the known candidates; falling back to %s", *rpcdURL)
		resolvedRPCd = *rpcdURL
	}

	addr := fmt.Sprintf("%s:%d", *listen, *port)
	modules.StartHistoryCollector()
	modules.StartMonitor()
	modules.StartNetPulseAgent(version)
	modules.StartMQTT(version)
	modules.StartSelfUpdateScheduler(version)
	modules.StartParentalScheduler()
	modules.StartQuotaScheduler()
	// The monitoring side links to this panel, so it has to know where it
	// answers rather than assume a default.
	modules.SetPanelPort(*port)
	modules.StartFleetDiscovery(version, *port)
	modules.StartPoEWatchdog()
	modules.StartBanipWarmup()
	modules.StartAnnouncements()
	// The login form posts the router's root password, so how the panel
	// listens is a security decision, not a preference. With -tls it serves
	// HTTPS on the same port: plaintext then fails at the handshake, which
	// is the point - a redirect cannot protect a password already sent to
	// it.
	scheme, srv := "http", &http.Server{Addr: addr, Handler: server.New(resolvedRPCd, version, *useTLS)}
	serve := srv.ListenAndServe
	if *useTLS {
		wanted, wantedKey := server.ResolveCertPaths(*tlsCert, *tlsKey)
		certs, certFile, _, err := server.OpenCertificate(*tlsCert, *tlsKey)
		if err != nil {
			// No usable pair anywhere. Never fall back to plaintext: a panel
			// quietly serving the password in clear after HTTPS was asked
			// for is worse than one that refuses to start, because nothing
			// says so.
			log.Fatalf("-https: no usable certificate (%s and %s): %v", wanted, wantedKey, err)
		}
		if certFile != wanted {
			log.Printf("-https: %s could not be used, serving %s instead", wanted, certFile)
		}
		srv.TLSConfig = certs.TLSConfig()
		serve = func() error { return srv.ListenAndServeTLS("", "") }
		scheme = "https"
	}
	log.Printf("netgrip %s listening on %s://%s (rpcd: %s)", version, scheme, addr, resolvedRPCd)
	if err := serve(); err != nil {
		// One-shot actionable hint instead of a respawn loop of bare
		// "address already in use" lines (#210).
		log.Printf("cannot listen on %s: %v", addr, err)
		if strings.Contains(err.Error(), "address already in use") {
			log.Printf("port %d is busy; pick another with -port (GL.iNet firmware serves its own web UI on 8080)", *port)
		}
		log.Fatal(err)
	}
}
