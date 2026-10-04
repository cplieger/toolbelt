# Configuration

This page lists every `Config` field, the helpers that fill `Config.Refresh` from an environment value, and every field a manifest entry can carry. It is for a developer calling `toolbelt.New`.

## Config fields

`ConfigDir` and `ToolsDir` are required. Every other field is optional.

| Field | Purpose |
| --- | --- |
| `ConfigDir` | The directory that holds `tools.json` and `tools-state.json`. Required |
| `ToolsDir` | The install tree: `bin/` (the one directory to put on `PATH`), `opt/<name>/<version>/`, `npm/` and `python/`. Required |
| `CatalogPath` | The catalog baked into your image, and the first-boot or offline fallback when `Refresh` is set |
| `Refresh` | Runtime catalog refresh: the catalog URL, the schedule interval (0 = on demand only) and the names checked before each swap. Nil keeps the baked catalog |
| `CatalogOverlays` | Your overlay files, applied again to every catalog the engine loads, so the patches survive a refresh |
| `Seed` | The manifest written when none exists. Nil writes an empty manifest |
| `System` | Binaries baked into your image, reported read-only in `Inventory` |
| `KeepVersions` | How many replaced versions stay under `opt/<name>/` for rollback. 0 means the default of 1, and a negative value keeps none |
| `VerifyRootIntegrity` | Refuse to start over an unsafe tools tree. Off by default. See below |
| `OnJobChanged` | Receives every job state change. Must not block. Nil is silent |
| `OnJobOutput` | Receives a running job's output lines in batches. Must not block. Nil is silent |
| `Logger` | The `slog` logger. Nil uses `slog.Default()` |

When `CatalogPath` is missing, an entry with complete install data can still install. An entry that relies on the catalog for its source or definition fails with an error that names the missing knowledge.

An overlay patch carries display fields and `essential`, which makes the engine refuse to remove that tool. An entry an overlay adds must embed any aqua definition inline, because there is no registry checkout to read at run time.

### Root integrity check

With `VerifyRootIntegrity` set, `New` refuses to start when `ConfigDir`, `ToolsDir` or one of `bin/`, `opt/`, `npm/`, `npm/bin`, `python/` and `python/bin` exists and fails a check. Every listed path must be a directory that is not a symlink, that only its owner can write and that the engine can inspect. `ConfigDir` may live outside `ToolsDir`, and `ToolsDir`'s managed subdirectories must resolve inside the tools tree. A path that does not exist yet is skipped.

The check only reports. It changes no mode and creates or repairs nothing. The error matches `ErrRootIntegrity` with `errors.Is`, and `errors.As` gives a `*RootIntegrityError` naming every path that failed. Turn it on when the tools tree lives on a volume someone else controls and your server runs privileged.

## Catalog refresh helpers

- `DefaultCatalogURL` is the latest-download URL of the published catalog.
- `ParseCatalogRefresh(RefreshEnv(raw), RefreshEnvName(name))` turns an environment value into `Refresh.Interval`. An empty or unreadable value gives the default of 24h. Other durations are kept between 1h and 30d. `off`, `disabled` and `0` turn the schedule off, and an on-demand refresh still works.
- `ParseRequireList(raw)` reads a list of tool names for `Refresh.Require`, one per line. Lines starting with `#` and blank lines are skipped.

## Manifest entry fields

Every field except the name is optional, and the catalog fills in the rest.

| Field | Purpose |
| --- | --- |
| `source` | Where the tool comes from, such as `aqua:cli/cli` or `npm:typescript` |
| `version` | The version to install. Empty means the latest |
| `pin` | Keep this version. Updates skip the entry |
| `disabled` | Make the entry a template that installs nothing |
| `requires` | Other tools this one needs, installed first |
| `version_args` | The arguments that make the tool print its version, for example `["--version"]`. The install check then compares the printed version |
| `install`, `uninstall`, `probe` | The bash scripts for a `manual` source |

A `_comment` array at the top of `tools.json` survives the engine's rewrites.

## The default seed

`DefaultSeed()` returns five disabled templates, the language servers `gopls`, `typescript-language-server`, `pyright` and `rust-analyzer`, plus the GitHub CLI `gh`. Nothing downloads until a template is enabled. Install knowledge comes from the catalog at that moment, so the seed never goes stale.

Language runtimes such as `node` and `go`, and required packages such as `typescript`, are left out of the seed. The engine adds a missing dependency when it installs, and a seeded row would only be a second place for its version to drift.
