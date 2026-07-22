# Contributing to toolbelt

Notes on the reconciler model, the invariants that make hand-edited
manifests safe, and the test suite. The three-state tool lifecycle and
the never-touch-unmanaged-files rule are the point of the library, so
most of this guide is about preserving them.

## What the library is

`toolbelt` provisions developer tools onto a persistent volume from a
declarative manifest, with install knowledge compiled into a read-only
catalog and execution serialized through a single-flight job queue. Two
consumers drive its shape: a UI-driven app (settings panel, SSE job
streaming via the `Config` callbacks) and a headless app (config-file
toggles, a loopback REST projection, a boot gate on `Reconcile`).

## Load-bearing invariants

- **The manifest is intent; presence means enabled.** `disabled: true`
  is the only template marker. Do not add an `enabled` field: absence of
  a flag must keep meaning "install this".
- **The reconciler converges both ways but never touches unmanaged
  files.** Uninstalls (disable, remove, reconcile-extras) act only on
  the engine-owned footprint recorded in `tools-state.json`
  (`ToolStatus.owned`). A same-name binary the engine never installed is
  invisible to cleanup paths, deliberately: volumes carry user-placed
  binaries that must keep working.
- **Hydration runs before any probe or plan.** Every install/update/
  reconcile job first completes sparse entries (no `source`) from the
  catalog, under the store lock. Reordering this wedges volumes with
  pre-existing binaries: an unmanaged binary satisfies the probe, the
  entry stays source-less, and the update path fails on an empty source
  forever. `TestHydration_LegacyBinaryDoesNotWedge` pins this.
- **Disabled entries stay offline.** Static catalog fields only; no
  version resolution, no fetches. `TestHydration_DisabledStaysOffline`
  pins it with a failing transport.
- **Install is policy-neutral.** `Install` (the retry verb) refuses
  disabled templates with `ErrDisabled`; enabling is an explicit
  `Patch{Disabled: false}`. The one sanctioned exception is
  `EnsureInstalled`, the programmatic "a product action needs this
  binary now" path, which enables and installs.
- **Checksum handling fails closed.** A declared checksum source that
  cannot be resolved, fetched, or matched aborts the install — never
  downgrade to unverified. `findChecksum` is algorithm-aware (BSD
  multi-algorithm tables, coreutils tables, bare digests); a format it
  cannot attribute confidently returns nothing and the install refuses.
- **The store is single-writer, in-process.** Every read-modify-write
  runs under the store mutex, and files are re-read per operation so
  out-of-band hand edits are picked up. Never link the library from a
  second process against the same data dir.
- **A fetched catalog never degrades the engine.** The runtime refresh
  (`catalogrefresh.go`) accepts a fetched catalog only after the full
  pipeline passes — parse, consumer overlays, the structural entry
  floor, and the consumer's `Require` verification; any failure keeps
  the current catalog and fails only the refresh job. The in-memory
  swap is an `atomic.Pointer` store; readers snapshot via `cat()` and
  never mix two catalogs mid-operation. The cache file persists the
  RAW fetched bytes (overlays re-apply at load), so the cache stays a
  faithful copy of the published artifact.
- **Job callbacks must not block.** `OnJobChanged` fires under the queue
  lock so transitions arrive in strict order; consumers fan out through
  their own non-blocking buffer (an SSE ring, a channel).

## Layout

Flat root package: `toolbelt.go` (Config, New, DefaultSeed),
`manifest.go` (store), `engine.go` (reconciler + public API), `jobs.go`
(queue), `install.go` (six backends), `versions.go` (latest-version
resolution via httpx), `aqua.go` (registry-definition evaluator),
`extract.go` (archive handling), `catalog.go` (reader + VerifyCatalog),
`wire.go` (result shapes). `httpapi/` is the REST projection built on
`webhttp` primitives. `cmd/toolcatalog/` is the catalog compiler command
(package main in this module — it shares the root's schema types and
verification semantics by construction and embeds the base overlay set).
Its TOML/YAML registry parsers stay out of consumer builds via module
graph pruning; they cost consumers a few `go.sum` metadata lines only.
It was a nested module with its own release lane until v2.2.x — folded
because the lane's root-first-then-lane release ordering and its
self-referential dependency bumps outweighed the go.sum hygiene, and a
single version stream removes compiler/engine schema skew entirely.

## Local development

The module targets the Go version pinned in `go.mod`. Use that toolchain
or newer.

```sh
go build ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

`cmd/toolcatalog` is part of this module — `go build ./...` covers it,
and `go run ./cmd/toolcatalog` runs your working tree's compiler
directly (no go.work, no cross-module setup).

### Linting and formatting

Lint config lives in `.golangci.yaml` (synced from `cplieger/ci`; change
it upstream). Formatting is `gofumpt` plus `gci` import grouping;
`golangci-lint run` reports unformatted files as issues, so format
before pushing.

```sh
golangci-lint run ./...
golangci-lint fmt
```

### Mutation testing

`.gremlins.yaml` configures [Gremlins](https://gremlins.dev) mutation
testing (synced from `cplieger/ci`). Run it locally to confirm new tests
actually kill mutants:

```sh
gremlins unleash .
```

## Test suite conventions

`go test -count=1 ./...` from the repo root. The suite runs real
installs against `httptest` servers and temp dirs (manual bash installs,
aqua artifact downloads with checksum verification, symlink-escape
rejection) — no mocks. Offline assertions use a failing transport: if a
path that must be network-free fetches anything, the test fails. Match
the file to the unit:

- `engine_test.go` — the ported behavioral suite: add/patch/remove,
  dependents cascade, aqua end-to-end (download → verify → extract →
  link → prune), queue-full rollbacks, symlink-escape rejection.
- `reconcile_test.go` — the reconciler state machine, hydration
  ordering, seeds, templates, checksum-file parsing.
- `aqua_test.go` / `versions_test.go` — evaluator fixtures (real
  registry files, JSON-converted so the root module needs no YAML
  dependency) and resolver behavior.
- `httpapi/httpapi_test.go` — route contract: status codes, the
  webhttp error envelope, toggle transitions, the dependents 409.

When adding an engine mutation, cover: the happy-path job, the
queue-full rollback (the manifest must never claim state no job will
realize), and the sentinel error mapping in `httpapi`. The
`cmd/toolcatalog` compiler is exercised against real registry checkouts
in its consumers' image builds (the `verify` gate), not unit-mocked here.

## Commits and PRs

Branch from `main`, keep changes focused with tests, and open a PR. This
account uses [Conventional Commits](https://www.conventionalcommits.org/)
parsed by git-cliff (`cliff.toml`), so the commit type drives the version
bump: `feat:`, `fix:`, `sec:`, and `chore:`/`docs:`/`refactor:`/`test:`
(no release). Write the subject as the changelog line a consumer would
read. `cmd/toolcatalog` commits version with the module like any other
package (use the `feat(toolcatalog):`/`fix(toolcatalog):` scope).

## Conduct & security

By participating you agree to the org-wide
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report security issues through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md) —
never in a public issue.
