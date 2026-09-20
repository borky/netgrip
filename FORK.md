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

## Waiting on upstream, not fork-only

These would go upstream tomorrow if they could:

| patch | blocked by |
|---|---|
| Reporting the panel port and the uplink policy to the monitoring agent | Needs `PanelPort` and `MultiWan` in a released `netpulse/agent`. Only builds with the local `go.work` until then. |
| The multi-WAN half of the fork-per-item performance work | The file it touches is not upstream yet (see the open multi-WAN PR). |

## The identifying-data hooks

`.git/hooks/pre-commit` scans the staged diff and `.git/hooks/commit-msg`
scans the message, both against the patterns in
`~/.claude/no-identifying-data.txt` — addresses from the LAN, hardware and
host names, credentials, personal identifiers. A match blocks the commit and
names the pattern that fired.

Hooks are not versioned, so **a fresh clone has no protection until they are
reinstalled**. Copy `no-identifying-data.py`, `pre-commit` and `commit-msg`
into the new clone's `.git/hooks/` and mark them executable. The pattern file
stays outside every repository on purpose: a list of what you want hidden is
itself a description of your network.

A missing pattern file warns instead of blocking, so a clone on another
machine can still commit. `git commit --no-verify` overrides once, deliberately.

## Building

The agent-reporting commits need the monitoring repo checked out beside this
one:

```sh
go work init . ../netpulse/agent   # once, and go.work stays untracked
go build ./...
```

Without the workspace, `GOWORK=off go build ./...` must still pass on `main`
and on any `feature/` branch — that is what proves a branch is PR-ready.
