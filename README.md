# toolbelt

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/toolbelt.svg)](https://pkg.go.dev/github.com/cplieger/toolbelt)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/toolbelt)](https://github.com/cplieger/toolbelt/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/toolbelt/badges/coverage.json)](https://github.com/cplieger/toolbelt/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/toolbelt/badges/mutation.json)](https://github.com/cplieger/toolbelt/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13646/badge)](https://www.bestpractices.dev/projects/13646)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/toolbelt/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/toolbelt)

> Declarative dev-tool provisioning for container dev boxes: manifest + catalog + reconciler engine

A standalone Go library that provisions developer tools (language servers, CLIs, runtimes, linters) onto a persistent volume, declaratively. A JSON manifest records intent: which tools, at which versions, enabled or disabled. A compiled catalog carries install knowledge for ~700 tools, sourced from the [mise](https://github.com/jdx/mise) and [aqua](https://github.com/aquaproj/aqua-registry) registries plus curated overlays. The engine reconciles installed state against intent through a single-flight job queue: enabled-but-missing tools are installed (checksum-verified when the registry definition declares a source), disabled-but-installed tools are uninstalled with their template kept, and unmanaged files are never touched.

Built for headless and UI consumers alike: everything is driven through the Go API, an optional REST projection (`toolbelt/httpapi`), or hand edits of the manifest file itself, which the engine picks up on its next operation.

## The model

Three data artifacts, all on the consumer's persistent volume:

| File | Owner | Purpose |
| --- | --- | --- |
| `tools.json` | user intent (engine-written, hand-editable) | which tools exist, versions, `pin`, `disabled` |
| `tools-state.json` | engine | what is actually installed, owned bin names, last error |
| `tool-catalog.json` | image build (baked fallback) + runtime refresh (`tool-catalog.cached.json` under `ConfigDir`) | install knowledge: sources, artifact templates, checksum locations, dependencies, registry license texts |

Tool lifecycle is a three-state machine the reconciler enforces in both directions:

- **absent**: not in the manifest. Unmanaged files under the tools dir are never touched.
- **disabled** (`"disabled": true`): a template. Recorded intent, nothing on disk; the engine uninstalls its owned footprint if present.
- **enabled** (present, no flag): installed; updated when unpinned.

Sources: `aqua:owner/repo` (binary artifacts with upstream checksum verification), `npm:pkg`, `pip:pkg` (via uv), `cargo:crate`, `go:module`, and a `manual` bash escape hatch. Ecosystem backends are themselves tools: an `npm:` install pulls `node` from the catalog automatically, `go:` pulls the Go toolchain, and so on.

## Install

`go get github.com/cplieger/toolbelt@latest`

## Usage

```go
engine, err := toolbelt.New(&toolbelt.Config{
    ConfigDir:   "/config",                        // tools.json + tools-state.json
    ToolsDir:    "/config/tools",                  // bin/, opt/, npm/, python/
    CatalogPath: "/opt/app/tool-catalog.json",     // baked fallback (image build)
    Seed:        toolbelt.DefaultSeed(),           // LSP templates, disabled
    Refresh: &toolbelt.CatalogRefresh{             // optional: runtime catalog refresh
        URL:      "https://example.com/tool-catalog.json",
        Interval: 24 * time.Hour,                  // 0 = on-demand only
        Require:  []string{"gopls", "gh"},         // verified before every swap
    },
})
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

// Boot: converge disk to intent, then gate whatever needs tools on the job.
if job, _ := engine.Reconcile(toolbelt.ReconcileMissing); job != nil {
    _, _ = engine.Wait(ctx, job.ID)
}

// Add a tool by name; the catalog supplies source, version, deps.
job, err := engine.Add(ctx, &toolbelt.AddRequest{Name: "gopls"})

// The enable/disable toggle: disabling uninstalls, the template stays.
on := true
job, err = engine.Patch("gopls", toolbelt.PatchRequest{Disabled: &on})
```

`DefaultSeed()` ships five disabled templates — the officially supported language servers plus the GitHub CLI (`gopls`, `typescript-language-server`, `pyright`, `rust-analyzer`, `gh`): nothing downloads until a template is enabled, and install knowledge hydrates from the catalog at enable time, so the seed never goes stale. Backend runtimes (`node`, `go`) and required packages (`typescript`) are not seeded: the engine auto-adopts missing dependencies at install time, while a seeded-but-disabled dependency would refuse dependent installs (a disabled entry is user policy).

### The REST projection

`toolbelt/httpapi` serves the engine over HTTP: inventory, catalog search, add, patch (the toggle verb), install, update, remove, jobs, cancel. It is a pure projection: no auth, no middleware; wrap it in your own stack (an origin-checked chain, a loopback-only gate).

```go
h := httpapi.Handler(engine, "/api/tools")
mux.Handle("/api/tools", h)
mux.Handle("/api/tools/", h)
```

Mutations return `202 {"job": ...}`; refusals are `409` with a coded envelope (`has_dependents` names the blockers, `disabled` marks install-on-a-template, `not_configured` marks a catalog refresh without `Config.Refresh`). Stream job progress via the `Config` callbacks or poll `GET .../jobs`.

### Runtime catalog refresh

The catalog is data on its own cadence: with `Config.Refresh` set, the engine fetches the published catalog on the configured interval and on demand via `RefreshCatalog` or the httpapi route (deliberately no fetch at construction — consumers fire the boot refresh with `RefreshCatalog` once their boot work is enqueued, as both apps do right after their boot reconcile), verifies it — a structural entry floor plus your `Require` list, the same offline checks as `toolcatalog verify` — re-applies any `Config.CatalogOverlays` display patches, persists the raw copy under `ConfigDir` (`tool-catalog.cached.json`, preferred over the baked file at the next boot), and swaps it in atomically. The last good catalog stands on any failure: a bad fetch degrades to yesterday's knowledge, never to a broken engine. `CatalogInfo()` reports what is loaded and where it came from (`baked`, `cached`, `remote`, or `none`), the registry refs, the generation timestamp, and the last refresh error.

### The catalog compiler

`cmd/toolcatalog` (an ordinary command in this module — the compiler and the engine share one version stream, so a catalog is always compiled under exactly the schema and verification semantics of the engine release that consumes it) compiles the catalog and verifies it against a required tool set. [tool-catalog](https://github.com/cplieger/tool-catalog) runs it on every registry bump and publishes the artifact consumers fetch; images run `verify` against their own required list at build. Its TOML/YAML registry parsers never reach consumer builds or binaries — Go's module graph pruning keeps commands you don't import out of everything but a few `go.sum` metadata lines:

```sh
go run github.com/cplieger/toolbelt/v2/cmd/toolcatalog@latest \
    -mise mise-checkout/registry -aqua aqua-registry-checkout/pkgs \
    -overlay overlays.json -refs mise=<ref>,aqua=<ref> -out tool-catalog.json

go run github.com/cplieger/toolbelt/v2/cmd/toolcatalog@latest \
    verify -catalog tool-catalog.json -require required-tools.txt
```

`verify` fails the build when a required name is missing from the catalog or its definition is unusable (no source, unparseable templates, no linux amd64/arm64 support), so registry drift surfaces at publish or image build instead of in a boot job. The command ships a base overlay set covering runtimes, forge CLIs, and the officially supported language servers agent CLIs probe for (`gopls`, `typescript-language-server`, `pyright`); it stamps a `generated` timestamp and embeds both registries' MIT license texts into the artifact, so the notice travels with every copy. Overlay merge semantics are the root module's `ApplyOverlay`, shared with the runtime refresh.

## API

### Engine

- `New(cfg *Config) (*Engine, error)` — construct + start (initializes the manifest files, seeding when absent and backing up a retired-format file; launches the job worker). `Close()` stops the worker.
- `Inventory() (*Inventory, error)` — the full read-side snapshot: every manifest entry joined with install state, the system group, the active job.
- `Search(q string) []CatalogEntry` — catalog lookup (empty query = the featured set), hiding names already in the manifest.
- `Add(ctx, *AddRequest) (*Job, error)` — record a new tool and enqueue its install; present-and-enabled is the default intent. `Disabled: true` adds a template instead (no job, returns nil).
- `Patch(name, PatchRequest) (*Job, error)` — merge fields; `Disabled` is the enable/disable toggle (false→true uninstalls and keeps the template, true→false installs), a version change enqueues a reinstall. `Force` permits disabling a tool enabled entries require.
- `Install(name) (*Job, error)` — retry an existing, enabled entry. Refuses templates with `ErrDisabled` (install is policy-neutral).
- `Update(names ...string) (*Job, error)` — refresh unpinned entries (or the named set).
- `Remove(name string, force bool) (*Job, []string, error)` — uninstall + delete the entry; refuses with the dependents named unless forced (force cascades).
- `Reconcile(mode) (*Job, error)` — converge disk to intent: `ReconcileMissing` installs missing enabled entries and uninstalls disabled-but-owned ones (zero network when converged); `ReconcileFull` also enqueues an update pass. Returns `(nil, nil)` on an empty manifest.
- `Wait(ctx, jobID) (*Job, error)` — block until a job settles (boot gates, synchronous flows).
- `EnsureInstalled(ctx, name) error` — synchronous "a product action needs this binary now": creates from the catalog, enables a disabled template, installs, waits.
- `Jobs() (active *Job, recent []*Job)` / `CancelJob(id) bool` — queue introspection and cancellation.
- `RefreshCatalog() (*Job, error)` — enqueue an on-demand catalog refresh (`ErrRefreshNotConfigured` without `Config.Refresh`).
- `CatalogInfo() CatalogInfo` — the live catalog's provenance: refs, generation timestamp, entry count, source, last refresh outcome, schedule state.

### Types and errors

`Tool` (manifest entry), `Manifest`, `ToolStatus`/`State` (machine state), `CatalogEntry`/`Catalog` (+ `VerifyCatalog`), `Inventory`/`ToolInfo`/`SystemTool`/`Job` (result shapes; also the httpapi wire shapes), `DefaultSeed()`. Sentinels: `ErrNotFound`, `ErrDisabled`, `ErrHasDependents` (match with `errors.Is`; `*DependentsError` carries the blocking names for `errors.As`).

### httpapi routes

| Route | Engine call | Notes |
| --- | --- | --- |
| `GET {prefix}` | `Inventory` | |
| `GET {prefix}/search?q=` | `Search` | results omit embedded install definitions |
| `POST {prefix}` | `Add` | 202 `{job}` (null for template adds) |
| `PATCH {prefix}/{name}` | `Patch` | the toggle verb; 409 `has_dependents` + names |
| `POST {prefix}/{name}/install` | `Install` | 409 `disabled` on templates |
| `POST {prefix}/update` | `Update` | optional `{"names": [...]}` body |
| `DELETE {prefix}/{name}?force=1` | `Remove` | 202 `{job, dependents}`; 409 without force |
| `GET {prefix}/jobs` | `Jobs` | active job carries the output tail |
| `POST {prefix}/jobs/{id}/cancel` | `CancelJob` | |
| `GET {prefix}/catalog` | `CatalogInfo` | provenance + freshness of the live catalog |
| `POST {prefix}/catalog/refresh` | `RefreshCatalog` | 202 `{job}`; 409 `not_configured` without `Config.Refresh` |

### toolcatalog (catalog compiler command)

`compile` (default): `-mise <dir> -aqua <dir> [-overlay file]... [-no-base-overlays] -refs k=v,... -out tool-catalog.json`. `verify`: `-catalog <file> -require <names-file>` — exits non-zero when a required name doesn't resolve to usable linux amd64+arm64 install knowledge. Versioned with the module (`go run github.com/cplieger/toolbelt/v2/cmd/toolcatalog@vX.Y.Z`); the historical `cmd/toolcatalog/vX.Y.Z` lane tags (≤ v2.2.0) remain resolvable for old builds.

## Configuration reference

| `Config` field | Purpose |
| --- | --- |
| `ConfigDir` | directory holding `tools.json` + `tools-state.json` (required) |
| `ToolsDir` | install tree root: `bin/` (the single PATH dir), `opt/<name>/<version>/`, `npm/`, `python/` (required) |
| `CatalogPath` | baked catalog path (the first-boot/offline fallback with `Refresh` set); missing degrades to manual/ecosystem sources with named errors for catalog-dependent entries |
| `Refresh` | runtime catalog refresh: the published-catalog URL, the schedule interval (0 = on-demand only), and the required names verified before every swap; nil keeps the baked catalog static |
| `CatalogOverlays` | consumer overlay files re-applied to every loaded catalog (display patches survive refreshes); entries they add must embed any aqua definition inline |
| `Seed` | manifest written when none exists (fresh volume or retired-format backup); nil seeds empty |
| `System` | image-baked binaries reported read-only in `Inventory` |
| `OnJobChanged` / `OnJobOutput` | job lifecycle + coalesced output callbacks (must not block); nil is silent |
| `Logger` | `slog` logger; nil uses the default |

Manifest entry fields: `source`, `version`, `pin` (freeze version), `disabled` (template), `requires`, and `install`/`uninstall`/`probe` for manual sources. Every field except the name is optional; the catalog completes the rest. A `_comment` array survives engine rewrites.

## Security model

- Aqua-sourced artifacts verify against the checksum source their registry definition declares (upstream `checksums.txt` and equivalents); an install without one is logged as unverified.
- Fetches ride an SSRF-guarded client (public-IP enforcement at the dial boundary, redirect policy, port allowlist) with transient-failure retry and rate-limit handling via [`cplieger/httpx`](https://github.com/cplieger/httpx).
- Downloads are size-capped (1 GiB); archive extraction rejects symlink members that escape the install tree; installs land in versioned directories swapped atomically.
- The `manual` source runs arbitrary bash by design: it is an operator escape hatch for single-principal volumes, equivalent in trust to editing the manifest itself.

## Scope notes

- Linux only (amd64, arm64). The aqua evaluator resolves definitions for linux and ignores other platforms.
- No apt/system-package backend: OS packages belong to the image or the consumer's entrypoint, not volume intent.
- The manifest store's single-writer guarantee is in-process. Run one engine per data directory; other processes go through the consumer's server.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0 — see [LICENSE](LICENSE).
