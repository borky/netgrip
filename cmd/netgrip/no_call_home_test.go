package main

// FORK: this file exists only in the fork. It is a new file rather than an
// edit to an upstream one so that it can never conflict with a sync.
//
// This panel runs on the router, and the fork sends no identifying data
// anywhere. The sibling project upstream added an anonymous instance ping with
// a persistent id (netpulse #822); nothing like it exists here, and this test
// is what keeps it that way. It fails on any request to either project's own
// host other than the announcements feed, which is a static file fetched with
// no parameters. Every new call home needs a human to read what it sends
// before it is added to the list below.
//
// It reads the source rather than asking the toolchain what it would link:
// a dependency-graph check sees only the host platform with default build
// tags, and this binary is built for ARM and MIPS routers. A file limited to
// one of those architectures, or behind a build tag, is read like any other.
//
// The word "telemetry" is deliberately not a marker: internal/modules has MQTT
// telemetry that goes to the owner's own Home Assistant broker, which is fine.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// projectDomain covers both projects' hosts and any new one: a single-host
// match let a new subdomain, or a host name split across two strings, through.
const projectDomain = "cloudless.club"

// allowedProjectURLs were each read and found to carry nothing that
// identifies the installation. Adding one here is a decision, not a fix for a
// failing test.
//
// They are matched as complete quoted literals, quotes included. Matching the
// bare URL let anything written after it through - "...announcements.json?id=x"
// passed, because the allowed part was removed before the search. What is
// built onto the URL in code is caught by the request itself instead: see
// internal/modules/no_call_home_announcements_test.go.
var allowedProjectURLs = []string{
	`"https://netgrip.cloudless.club/announcements.json"`, // static file, no parameters
}

func TestThePanelNeverCallsHome(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..")) // the repo, from cmd/netgrip
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot find the module root from %s: %v", root, err)
	}

	var hits []string
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			// The web app has no Go and a very large node_modules.
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || rel == "app" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		src := string(b)
		for _, allowed := range allowedProjectURLs {
			src = strings.ReplaceAll(src, allowed, "")
		}
		if strings.Contains(src, projectDomain) {
			hits = append(hits, rel+": refers to "+projectDomain+" other than the allowed feed")
		}
		if strings.Contains(src, "NETPULSE_TELEMETRY") {
			hits = append(hits, rel+": refers to NETPULSE_TELEMETRY")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A guard that reads nothing passes everything.
	if scanned < 50 {
		t.Fatalf("scanned only %d files under %s; the walk is broken, so this check proves nothing", scanned, root)
	}
	t.Logf("scanned %d source files", scanned)
	if len(hits) > 0 {
		t.Fatalf("this fork sends no identifying data anywhere, and a sync has added a call home:\n  %s\n\n"+
			"Read what it sends before deciding anything. See FORK.md.", strings.Join(hits, "\n  "))
	}
}
