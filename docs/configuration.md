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
| `KeepVersions` | How many replaced versions stay under `opt/<name>/` for rollback, the most recently installed first. 0 means the default of 1, and a negative value keeps none |
| `VerifyRootIntegrity` | Refuse to start over an unsafe tools tree. Off by default. See below |
| `TrustedUIDs` | Users whose ownership of, or write access to, a checked directory the root integrity check accepts, beside root and the account the engine runs as: an account you know is already privileged on the host. A negative entry makes `New` fail |
| `OnJobChanged` | Receives every job state change. Must not block. Nil is silent |
| `OnJobOutput` | Receives a running job's output lines in batches. Must not block. Nil is silent |
| `GitHubToken` | Returns the token for each `api.github.com` request, the engine's only token source. Nil or `""` sends none. An error fails the request. See [Security](security-model.md#network) |
| `Logger` | The `slog` logger. Nil uses `slog.Default()` |

When `CatalogPath` is missing, an entry with complete install data can still install. An entry that relies on the catalog for its source or definition fails with an error that names the missing knowledge.

An overlay patch carries display fields and `essential`, which makes the engine refuse to remove that tool. An entry an overlay adds must embed any aqua definition inline, because there is no registry checkout to read at run time.

### Root integrity check

With `VerifyRootIntegrity` set, `New` refuses to start when `ConfigDir`, `ToolsDir` or one of `bin/`, `opt/`, `npm/`, `npm/bin`, `npm/lib`, `npm/lib/node_modules`, `python/`, `python/bin`, `python/tools` and `python/interpreters` exists and fails a check. A path that does not exist yet is skipped. Every listed path must:

- be a directory and not a symlink, that the engine can inspect;
- belong to root, to the account the engine runs as or to a user in `TrustedUIDs`, and so must every directory the system passes through to reach it, each symlink's target and every `..` included;
- be writable by nobody else, by its mode or by a POSIX.1e or NFSv4 access-control list, and so must every directory above it. A sticky directory above it, such as `/tmp`, may be writable by others, unless its list lets another account take it or rewrite the list. Each user in `TrustedUIDs` counts as root. No group does, group 0 included, so a directory above the tree that its group can write, such as a `root:root 0775` one, needs `chmod g-w`;
- for `ToolsDir`'s managed subdirectories, resolve inside the tools tree. `ConfigDir` may live outside it.

`New` checks again after it has created `ConfigDir`, `ToolsDir` and `bin/`, so a root it created and the filesystem stored as writable by another account refuses to start as well, leaving what it created in place.

The check only reports. It changes no mode, owner or list, and creates or repairs nothing. It judges those directories, not the files beneath them. The error matches `ErrRootIntegrity` with `errors.Is`, and `errors.As` gives a `*RootIntegrityError` naming each path that failed and the first reason it failed. A failure in a directory above the tree is reported on every path beneath it. Turn it on when the tools tree lives on a volume someone else controls and your server runs privileged.

## Catalog refresh helpers

- `DefaultCatalogURL` is the latest-download URL of the published catalog.
- `ParseCatalogRefresh(RefreshEnv(raw), RefreshEnvName(name))` turns an environment value into `Refresh.Interval`. An empty or unreadable value gives the default of 24h. Other durations are kept between 1h and 30d. `off`, `disabled` and `0` turn the schedule off, and an on-demand refresh still works.
- `ParseRequireList(raw)` reads a list of tool names for `Refresh.Require`, one per line. Lines starting with `#` and blank lines are skipped.

## Manifest entry fields

Every field except the name is optional, and the catalog fills in the rest.

| Field | Purpose |
| --- | --- |
| `source` | Where the tool comes from, such as `aqua:cli/cli` or `npm:typescript` |
| `version` | The version to install. Empty means the latest. A hand edit of an installed entry's version applies at its next install or reconcile. An unpinned `apt:` entry installs apt's candidate and takes its version |
| `pin` | Keep this version. Updates skip the entry. A pinned `apt:` entry installs exactly its version, downgrading if needed, and also holds the package |
| `disabled` | Make the entry a template that installs nothing |
| `requires` | Other tools this one needs, installed first. A name with no enabled entry is added from the catalog or enabled at the entry's next install or reconcile, including after a hand edit |
| `python` | For a `pip:` entry, the Python version uv builds the tool on, such as `3.14`. Empty takes the newest. A change through `Patch` reinstalls an enabled tool, and a hand edit applies at its next install or reconcile |
| `version_args` | The arguments that make the tool print its version, for example `["--version"]`. The install check then compares the printed version. When unset, an entry the catalog completes takes the catalog's, and otherwise the check runs `--version` and only requires an answer. An argument may not contain a NUL byte |
| `install`, `uninstall`, `probe` | The bash scripts for a `manual` source |

A `_comment` array at the top of `tools.json` survives the engine's rewrites.

## The default seed

`DefaultSeed()` returns four disabled templates, the language servers `gopls`, `typescript-language-server`, `pyright` and `rust-analyzer`. Nothing downloads until a template is enabled. Install knowledge comes from the catalog at that moment, so the seed never goes stale.

Language runtimes such as `node` and `go`, and required packages such as `typescript`, are left out of the seed. The engine adds a missing dependency when it installs, and a seeded row would only be a second place for its version to drift.
