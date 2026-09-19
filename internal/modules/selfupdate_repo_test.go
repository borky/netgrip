package modules

import (
	"strings"
	"testing"
)

// The default has to stay upstream: a normal install must keep getting
// upstream's releases with no configuration at all.
func TestUpdateRepoDefaultsToUpstream(t *testing.T) {
	restoreUpdateRepo(t)
	if got := UpdateRepo(); got != defaultUpdateRepo {
		t.Fatalf("default repo = %q, want %q", got, defaultUpdateRepo)
	}
	if url := releasesAPIURL(); !strings.Contains(url, defaultUpdateRepo) {
		t.Errorf("default URL = %q, want it to name %q", url, defaultUpdateRepo)
	}
}

// The point of the setting: a build that is not upstream's asks its own
// releases, so accepting an update cannot replace it with a binary that does
// not contain what this one added.
func TestSetUpdateRepoRedirectsTheCheck(t *testing.T) {
	restoreUpdateRepo(t)
	SetUpdateRepo("someone/netgrip")
	if got := UpdateRepo(); got != "someone/netgrip" {
		t.Fatalf("repo = %q, want someone/netgrip", got)
	}
	url := releasesAPIURL()
	if !strings.Contains(url, "someone/netgrip") {
		t.Errorf("URL = %q, want it to name the configured repo", url)
	}
	if strings.Contains(url, defaultUpdateRepo) {
		t.Errorf("URL = %q still points at upstream", url)
	}
}

// A malformed value must leave the default alone rather than build a URL that
// 404s on every check: silently never updating is worse than not being
// configurable, because nothing says the setting was wrong.
func TestSetUpdateRepoRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "   ", "netgrip", "/netgrip", "owner/", "a/b/c"} {
		t.Run("bad="+bad, func(t *testing.T) {
			restoreUpdateRepo(t)
			SetUpdateRepo(bad)
			if got := UpdateRepo(); got != defaultUpdateRepo {
				t.Errorf("SetUpdateRepo(%q) changed the repo to %q", bad, got)
			}
		})
	}
}

// Surrounding whitespace and a trailing slash are the shapes a value picked up
// from an env file or an init script arrives in.
func TestSetUpdateRepoTrims(t *testing.T) {
	restoreUpdateRepo(t)
	SetUpdateRepo("  someone/netgrip/  ")
	if got := UpdateRepo(); got != "someone/netgrip" {
		t.Errorf("repo = %q, want someone/netgrip", got)
	}
}

func restoreUpdateRepo(t *testing.T) {
	t.Helper()
	orig := updateRepo
	t.Cleanup(func() { updateRepo = orig })
	updateRepo = defaultUpdateRepo
}
