# toolbelt

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/toolbelt/v3.svg)](https://pkg.go.dev/github.com/cplieger/toolbelt/v3) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/toolbelt)](https://github.com/cplieger/toolbelt/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/toolbelt/badges/mutation.json)](https://github.com/cplieger/toolbelt/issues?q=label%3Agremlins-tracker)

toolbelt lets your Go server install, update and remove the developer tools its users ask for, on a persistent volume, while it runs.

It replaces the image rebuild or install script a web IDE or agent sandbox would otherwise need for every new CLI, language server or runtime. It runs on Linux amd64 and arm64, needs Go 1.27.1 or later and is licensed under Apache-2.0. At run time it depends on `expr-lang/expr`, `hashicorp/go-version`, `golang.org/x/mod` and eight libraries by the same author.

## Why use it

toolbelt is built for a containerized dev environment whose users add tools from a settings page, a config file or an agent.

- A JSON manifest records each tool, its version and whether it is pinned or disabled. The engine installs what is missing, uninstalls what is disabled and never touches files it did not install.
- A catalog of about 900 tools, compiled from the mise and aqua registries, gives each tool's source, version and dependencies, so users add tools by name.
- It installs from eight sources, `aqua:`, `release:`, `apt:`, `npm:`, `pip:`, `cargo:`, `go:` and `manual`, and adds the runtime a language source needs, such as `node` for `npm:`. A `manual` entry runs your own bash script, with the trust of a manifest edit.
- Installs run one at a time as jobs you can watch, wait on and cancel, through Go or a REST handler.

Consider [aqua](https://github.com/aquaproj/aqua) if you want a command-line tool that pins versions per project for teams and CI, kept current by Renovate.

## Install

```sh
go get github.com/cplieger/toolbelt/v3@latest
```

## Usage

```go
engine, err := toolbelt.New(&toolbelt.Config{
    ConfigDir:   "/config",                    // tools.json and tools-state.json
    ToolsDir:    "/config/tools",              // bin/, opt/, npm/, python/
    CatalogPath: "/opt/app/tool-catalog.json", // the catalog baked into your image
    Seed:        toolbelt.DefaultSeed(),       // five disabled templates
    Refresh: &toolbelt.CatalogRefresh{         // optional: fetch newer catalogs
        URL:      toolbelt.DefaultCatalogURL,
        Interval: 24 * time.Hour, // 0 = on demand only
        Require:  []string{"gopls", "gh"},
    },
})
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

// At boot, install what the manifest asks for and wait for it.
// enqueued is false when the manifest is empty and nothing is installed.
if job, enqueued, _ := engine.Reconcile(toolbelt.ReconcileMissing); enqueued {
    _, _ = engine.Wait(ctx, job.ID)
}

// Then fetch a newer catalog. New never fetches on its own.
_, _ = engine.RefreshCatalog()

// Add a tool by name. The catalog supplies its source, version and dependencies.
job, err := engine.Add(ctx, &toolbelt.AddRequest{Name: "gopls"})

// Disable it. The binary is uninstalled and the entry stays as a template.
disabled := true
job, err = engine.Patch("gopls", toolbelt.PatchRequest{Disabled: &disabled})
```

`DefaultSeed` writes five disabled templates on a fresh volume: `gopls`, `typescript-language-server`, `pyright`, `rust-analyzer` and `gh`. Nothing downloads until one is enabled. Installed tools are linked into `bin/` under `ToolsDir`, so put that directory on the `PATH` of whatever runs them. [The catalog](docs/catalog.md) explains when the engine fetches a newer catalog. To serve the engine over HTTP, mount `httpapi.Handler(engine, "/api/tools")` behind your own authentication. [The REST handler](docs/http-api.md) lists its routes.

## API

- `New` and `Close` start and stop an engine. `Inventory`, `Search` and `SearchWithCounts` read the manifest, the install state and the catalog.
- `Add`, `Patch`, `Install`, `Update`, `Remove`, `RemoveWithDependents` and `Reconcile` change the manifest or the disk, each through a job. `EnsureInstalled` installs a tool and waits for it.
- `Jobs`, `Wait` and `CancelJob` follow the job queue. `RefreshCatalog` and `CatalogInfo` refresh and describe the catalog.
- `ErrNotFound`, `ErrDisabled`, `ErrHasDependents`, `ErrEssential`, `ErrUnknownJob`, `ErrRefreshNotConfigured` and `ErrRootIntegrity` match with `errors.Is`.
- `httpapi.Handler` serves the engine over HTTP, and `cmd/toolcatalog` compiles and checks a catalog.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/toolbelt/v3).

## What it guarantees

- Uninstalls remove only the files the engine recorded when it installed the tool. A binary of the same name that it did not install stays.
- A download whose aqua registry definition declares a checksum installs only when that checksum matches. A tool with no declared checksum installs unverified, and its state says so.
- A tool counts as installed only when its binary runs. A binary the system cannot start fails the install, and the error carries the system's reason, such as a missing library.
- A new version is written in full and flushed to disk before it replaces the old one. A failed install leaves the previous version in place.
- A newer catalog replaces the current one only after it passes the same checks as `toolcatalog verify`. A bad fetch changes nothing.
- Asking for a tool also installs every tool it depends on, first. A removal that would break an enabled tool is refused and names it.

[Security](docs/security.md) covers checksums, downloads, archives and the binaries the engine runs.

## Unsupported by design

- Windows and macOS.
- Removing a Debian package. Removing an `apt:` entry leaves the package installed, because other packages may need it.
- Two processes sharing one data directory. Run one engine per directory and send other processes through your server.
- Authentication in the REST handler. Wrap it in your own middleware.

## Documentation

- [How toolbelt works](docs/how-it-works.md) explains the manifest, the tool lifecycle, dependencies and every engine call.
- [Configuration](docs/configuration.md) lists every `Config` field and manifest field.
- [The catalog](docs/catalog.md) covers runtime refresh and the `toolcatalog` compiler.
- [The REST handler](docs/http-api.md) lists the routes, the refusal codes and the cache policy.
- [Security](docs/security.md) describes what the engine checks and what it trusts.

## Credits

- The catalog is compiled from the [mise registry](https://github.com/jdx/mise) and the [aqua registry](https://github.com/aquaproj/aqua-registry). The `aqua:` source reads aqua's package definitions directly, templates and expressions included.
- The `release:` source picks a release asset in the order [ubi](https://github.com/houseabsolute/ubi) uses, a GitHub and GitLab release installer.
- [tool-catalog](https://github.com/cplieger/tool-catalog), by the same author, publishes the compiled catalog that `DefaultCatalogURL` points at.

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions and how to run the checks locally.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).

Third-party attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
