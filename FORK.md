# What this fork changes, and why it is not upstream

This branch (`develop`) is upstream's `main` plus the patches below. Anything
generally useful is offered upstream first; what remains here is listed with
the reason it stays.

Keep this file current — it is what tells you, months later, which divergence
was deliberate.

## Branches

| branch | meaning |
|---|---|
| `main` | a mirror of upstream. Fast-forward only, never commit to it. |
| `develop` | the product: upstream plus the patches below. |
| `feature/<name>` | new work, cut from `main` so it can become a PR unchanged. |

Releases are tags on `develop`. Rebasing `develop` during a sync never
disturbs them.

## Syncing with upstream

```sh
git fetch upstream
git checkout main && git merge --ff-only upstream/main && git push origin main
git rebase -i upstream/main develop
```

During the rebase, drop any commit upstream has already taken. GitHub
squash-merges, so your original commits do not disappear by themselves and
will conflict. Identify them by content, not by subject:

```sh
git grep -c '<a symbol the commit introduced>' upstream/main -- '*.go'
```

Then: `GOWORK=off go build ./...`, `go test ./...`, deploy to a router, and
only then tag.

## Fork-only patches

| patch | why it is not upstream |
|---|---|
| Configurable update source, defaulting to this fork (`selfupdate.go`, `cmd/netgrip/main.go`, `netgrip.init`) | Offered as gnacho/netgrip#345 and **declined**: upstream ties self-update to its own releases on purpose and would rather a non-upstream build switched self-update off than carry a config surface for a case it does not have. Kept anyway, for a narrower reason than the PR claimed: this fork is built from source and keeps the scheduler off (`netgrip.selfupdate.enabled='0'`), but that flag only governs the **scheduler** — `POST /api/selfupdate` applies an update without consulting it, so the panel would still offer upstream's release (a source build reports version `dev`, which compares as older than any tag) and one click would replace it. The patch removes the false "update available" and makes that click harmless. |
| Manual NetPulse pairing card shown (`app/src/pages/System.tsx`) | Upstream hides it on purpose. We need it: the monitoring server is on another subnet, so the LAN-broadcast discovery can never find it. |
| `.gitignore` for local build outputs and `go.work` | Only relevant to this working style. |

Upstream said it would reconsider "if a real downstream with its own release
channel ever shows up". Not worth pursuing while this fork is built from
source for its own devices: there is no release channel to keep current, and
`fork-release.yml` exists for the day there is. Revisit if the fork gets
users who install binaries rather than build them.

Nine PRs have merged upstream, including the whole multi-WAN feature
(gnacho/netgrip#337, merged as a merge commit rather than a squash — which is
why a rebase dropped all thirteen of this branch's copies automatically).

## Upstream behaviour this fork accepts as-is

| behaviour | decision |
|---|---|
| The panel polls `https://netgrip.cloudless.club/announcements.json` every 6 hours and renders the result as a ribbon (upstream #389) | **Left alone, deliberately.** It means this build makes a recurring outbound call to upstream's domain and upstream can show text and a link inside the panel. Acceptable while the only user is the person who builds it — and it is how a security notice would arrive. No patch is needed to change course later: upstream already honours `NETGRIP_ANNOUNCEMENTS_URL`, so the init script can point it elsewhere, or at something unreachable to silence it (there is no explicit off switch). Revisit if the fork gets other users. |

## Waiting on upstream, not fork-only

These would go upstream tomorrow if they could:

| patch | blocked by |
|---|---|
| Reporting the panel port and the uplink policy to the monitoring agent | Needs `PanelPort` and `MultiWan` in a released `netpulse/agent`. Only builds with the local `go.work` until then. |
| The multi-WAN half of the fork-per-item performance work | **No longer blocked**: the multi-WAN module merged upstream (gnacho/netgrip#337), so this is offered as its own PR. It needed porting rather than cherry-picking - upstream's merged version keeps the tracker-state reading inline in `MwanActiveUplink`, while this branch had already factored it out as `mwanLiveState` in the agent-reporting commit above. |

## The identifying-data hooks

`.git/hooks/pre-commit` scans the staged diff and `.git/hooks/commit-msg`
scans the message, both against the patterns in
`~/.claude/no-identifying-data.txt` — addresses from the LAN, hardware and
host names, credentials, personal identifiers. A match blocks the commit and
names the pattern that fired.

Hooks are not versioned, so **a fresh clone has no protection until they are
reinstalled**. Copy `no-identifying-data.py`, `no-ai-trailers.py`,
`pre-commit` and `commit-msg` into the new clone's `.git/hooks/` and mark them
executable. The pattern file
stays outside every repository on purpose: a list of what you want hidden is
itself a description of your network.

A missing pattern file warns instead of blocking, so a clone on another
machine can still commit. `git commit --no-verify` overrides once, deliberately.

## The AI-trailer hook

`.git/hooks/no-ai-trailers.py`, also run from `commit-msg`, refuses a message
carrying `Co-Authored-By` for an AI tool, a `generated with` footer or the
robot emoji. Upstream asked for this on PR #387: *"This repo keeps AI tooling
out of the recorded history."*

It is a hook rather than a note to self because the cost of forgetting is not
a tidy-up. Upstream force-pushed `main` to strip such trailers from an
already-merged branch: the content was byte-identical, verified by tree hash,
but every commit hash from the multiWAN merge onward changed, which silently
broke every open PR based on the old history — GitHub fell back to a merge
base 200 commits earlier and showed 342 changed files instead of 27. Three
branches had to be rebased with `git rebase --onto upstream/main <old-base>`
and force-pushed.

Unlike the identifying-data check it needs no pattern file, so it works in a
fresh clone as soon as the hooks are copied in. A human co-author is still
allowed; only values naming a tool or an assistant's service address match.

**It cannot catch every path.** `git rebase` and `git filter-branch` do not run
`commit-msg`, so a trailer can still arrive through a replay of older commits.
To clean a branch:

```sh
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter 'sed "/^Co-Authored-By: Claude/d"' upstream/main..HEAD
```

## Building

The agent-reporting commits need the monitoring repo checked out beside this
one:

```sh
go work init . ../netpulse/agent   # once, and go.work stays untracked
go build ./...
```

Without the workspace, `GOWORK=off go build ./...` must still pass on `main`
and on any `feature/` branch — that is what proves a branch is PR-ready.

## Invariants learned the hard way

Both of these cost a lockout on a live router before they were written down.
They are enforced in code and pinned by tests; this is the short version of
why, so nobody relaxes them by accident.

**A cookie name that has ever been issued with `Secure` can never be used
from a plaintext origin again.** A browser refuses to let an insecure origin
overwrite a `Secure` cookie of the same name (RFC 6265bis 5.4, "leave secure
cookies alone"), and the same rule blocks deleting it — so no server can
clean it up. Turning the panel's HTTPS off therefore made a correct password
produce a 204 and no session, with nothing in any log to say why. The session
cookie now has one name per transport and **neither is the name it used to
have**: `__Secure-netgrip_session` over TLS, `netgrip_http_session` over
plain HTTP, and the old `netgrip_session` is read but never issued.
See `internal/server/server.go` and `session_cookie_test.go`.

**"Can it be served", "should it be offered" and "what is on the wire" are
three different questions.** Answering any of them with a proxy for another
is how the Access card came to offer a certificate that saving refused, to
report a pair that was not in use, and to say "Serving plain HTTP" over
HTTPS. `internal/certs` holds the two predicates — `LoadPair` for *can this
be served*, `Usable` for *is it worth keeping* — so the listener and the card
cannot drift apart. Reporting follows what the listener would really do;
offering follows what saving will really accept.

The general rule behind both: report what is observable, never what was
configured or intended, and where a check stands in for the real thing, make
it the same check the real consumer makes.
