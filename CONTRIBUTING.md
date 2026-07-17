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
  invisible to cleanup paths, deliberately: migration volumes carry
  pre-engine binaries that must keep working.
- **Hydration runs before any probe or plan.** Every install/update/
  reconcile job first completes sparse entries (no `source`) from the
  catalog, under the store lock. Reordering this wedges migration
  volumes: a legacy binary satisfies the probe, the entry stays
  source-less, and the update path fails on an empty source forever.
  `TestHydration_LegacyBinaryDoesNotWedge` pins this.
- **Disabled entries stay offline.** Static catalog fields only; no
  version resolution, no fetches. `TestHydration_DisabledStaysOffline`
  pins it with a failing transport.
- **Install is policy-neutral.** `Install` (the retry verb) refuses
  disabled templates with `ErrDisabled`; enabling is an explicit
  `Patch{Disabled: false}`. The one sanctioned exception is
  `EnsureInstalled`, the programmatic "a product action needs this
  binary now" path, which enables and installs.
- **The store is single-writer, in-process.** Every read-modify-write
  runs under the store mutex, and files are re-read per operation so
  out-of-band hand edits are picked up. Never link the library from a
  second process against the same data dir.
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
`webhttp` primitives. `cmd/toolcatalog/` is a nested Go module (its own
release lane) so the TOML/YAML registry parsers never reach a consumer's
`go.sum`; it depends on the root module for the schema types.

## Tests

`go test -count=1 ./...` from the repo root. The suite runs real
installs against `httptest` servers and temp dirs (manual bash installs,
aqua artifact downloads with checksum verification, symlink-escape
rejection) — no mocks. Offline assertions use a failing transport: if a
path that must be network-free fetches anything, the test fails. The
`cmd/toolcatalog` lane is exercised against real registry checkouts in
CI-adjacent smoke runs; its JSON output contract with the root reader is
pinned by the `testdata/` fixtures.

When adding an engine mutation, cover: the happy path job, the
queue-full rollback (the manifest must never claim state no job will
realize), and the sentinel error mapping in `httpapi`.

## Conventions

Conventional commits (the changelog is generated), gofumpt/gci via
`golangci-lint fmt`, and the shared `.golangci.yaml` gate. CI configs
sync from a central repo — do not hand-edit workflow files.
