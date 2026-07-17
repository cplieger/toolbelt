# toolbelt

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/toolbelt.svg)](https://pkg.go.dev/github.com/cplieger/toolbelt)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/toolbelt)](https://github.com/cplieger/toolbelt/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/toolbelt/badges/coverage.json)](https://github.com/cplieger/toolbelt/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/toolbelt/badges/mutation.json)](https://github.com/cplieger/toolbelt/issues?q=label%3Agremlins-tracker)
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
| `tool-catalog.json` | image build (`cmd/toolcatalog`) | install knowledge: sources, artifact templates, checksum locations, shims, dependencies |

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
    CatalogPath: "/opt/app/tool-catalog.json",     // compiled at image build
    Seed:        toolbelt.DefaultSeed(),           // LSP templates, disabled
})
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

// Boot: converge disk to intent, then gate whatever needs tools on the job.
if job, _ := engine.Reconcile(toolbelt.ReconcileMissing); job != nil {
    _, _ = engine.Wait(ctx, job.ID)
}

// Add a tool by name; the catalog supplies source, version, shims, deps.
job, err := engine.Add(ctx, &toolbelt.AddRequest{Name: "gopls"})

// The enable/disable toggle: disabling uninstalls, the template stays.
on := true
job, err = engine.Patch("gopls", toolbelt.PatchRequest{Disabled: &on})
```

`DefaultSeed()` ships four disabled templates (`gopls`, `tsc-native`, `pyrefly`, `gh`): nothing downloads until a template is enabled, and install knowledge hydrates from the catalog at enable time, so the seed never goes stale.

### The REST projection

`toolbelt/httpapi` serves the engine over HTTP: inventory, catalog search, add, patch (the toggle verb), install, update, remove, jobs, cancel. It is a pure projection: no auth, no middleware; wrap it in your own stack (an origin-checked chain, a loopback-only gate).

```go
h := httpapi.Handler(engine, "/api/tools")
mux.Handle("/api/tools", h)
mux.Handle("/api/tools/", h)
```

Mutations return `202 {"job": ...}`; refusals are `409` with a coded envelope (`has_dependents` names the blockers, `disabled` marks install-on-a-template). Stream job progress via the `Config` callbacks or poll `GET .../jobs`.

### The catalog compiler

`cmd/toolcatalog` (a nested module, so its registry-parsing dependencies never enter your `go.sum`) compiles the catalog at image build and verifies it against your required tool set:

```sh
go run github.com/cplieger/toolbelt/cmd/toolcatalog@latest \
    -mise mise-checkout/registry -aqua aqua-registry-checkout/pkgs \
    -overlay overlays.json -refs mise=<ref>,aqua=<ref> -out tool-catalog.json

go run github.com/cplieger/toolbelt/cmd/toolcatalog@latest \
    verify -catalog tool-catalog.json -require required-tools.txt
```

`verify` fails the build when a required name is missing from the catalog or its definition is unusable (no source, unparseable templates, no linux amd64/arm64 support), so registry drift surfaces at image build instead of in a boot job. The lane ships a base overlay set covering runtimes, forge CLIs, and language servers with the wrapper-script shims agent CLIs probe for (`typescript-language-server`, `pyright`, `pyright-langserver`).

## Configuration reference

| `Config` field | Purpose |
| --- | --- |
| `ConfigDir` | directory holding `tools.json` + `tools-state.json` (required) |
| `ToolsDir` | install tree root: `bin/` (the single PATH dir), `opt/<name>/<version>/`, `npm/`, `python/` (required) |
| `CatalogPath` | compiled catalog path; missing degrades to manual/ecosystem sources with named errors for catalog-dependent entries |
| `Seed` | manifest written when none exists (fresh volume or retired-format backup); nil seeds empty |
| `System` | image-baked binaries reported read-only in `Inventory` |
| `OnJobChanged` / `OnJobOutput` | job lifecycle + coalesced output callbacks (must not block); nil is silent |
| `Logger` | `slog` logger; nil uses the default |

Manifest entry fields: `source`, `version`, `pin` (freeze version), `disabled` (template), `requires`, `shims` (wrapper scripts, full command lines), and `install`/`uninstall`/`probe` for manual sources. Every field except the name is optional; the catalog completes the rest. A `_comment` array survives engine rewrites.

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
