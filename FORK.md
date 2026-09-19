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
| Update source defaults to this fork (`netgrip.init`) | The mechanism is upstream; only the default is ours. One line, deliberately. |
| Manual NetPulse pairing card shown (`app/src/pages/System.tsx`) | Upstream hides it on purpose. We need it: the monitoring server is on another subnet, so the LAN-broadcast discovery can never find it. |
| `.gitignore` for local build outputs and `go.work` | Only relevant to this working style. |

## Waiting on upstream, not fork-only

These would go upstream tomorrow if they could:

| patch | blocked by |
|---|---|
| Reporting the panel port and the uplink policy to the monitoring agent | Needs `PanelPort` and `MultiWan` in a released `netpulse/agent`. Only builds with the local `go.work` until then. |
| The multi-WAN half of the fork-per-item performance work | The file it touches is not upstream yet (see the open multi-WAN PR). |

## Building

The agent-reporting commits need the monitoring repo checked out beside this
one:

```sh
go work init . ../netpulse/agent   # once, and go.work stays untracked
go build ./...
```

Without the workspace, `GOWORK=off go build ./...` must still pass on `main`
and on any `feature/` branch — that is what proves a branch is PR-ready.
