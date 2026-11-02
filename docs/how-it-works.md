# How toolbelt works

This page explains the files the engine keeps, the life of a tool, how dependencies are handled and what each engine call does. It is for a developer wiring toolbelt into a server.

## Three files

The engine uses three data files. The manifest and the state live under `ConfigDir` on your persistent volume. The catalog is read from `Config.CatalogPath`, usually baked into your image, and a refreshed copy is cached under `ConfigDir`.

| File | Owner | Purpose |
| --- | --- | --- |
| `tools.json` | the user's intent. The engine writes it, and a person may edit it by hand | which tools exist, their versions, `pin` and `disabled` |
| `tools-state.json` | the engine | what is installed, the binary names each tool owns, the last error |
| the file at `Config.CatalogPath`, plus `tool-catalog.cached.json` under `ConfigDir` | your image build, and the engine once a runtime refresh succeeds | install knowledge: sources, download templates, checksum locations, dependencies, the registries' license texts |

The engine reads `tools.json` again on every operation, so a hand edit takes effect on the next call. It accepts only manifest schema version 2. Any other version fails `New`, and the engine never rewrites or backs up a manifest it does not recognise.

## The life of a tool

A tool is in one of three states, and the engine enforces each one in both directions.

- An absent tool is not in the manifest. Files under the tools directory that the engine did not install are never touched.
- A disabled tool, marked `"disabled": true`, is a template. It records the intent and has nothing on disk. If the engine installed it earlier, the engine uninstalls the files it owns.
- An enabled tool is present with no flag. It is installed, and updated when it is not pinned.

Installs land in versioned directories under `opt/<name>/<version>/`, and `bin/` holds the links that go on `PATH`. `KeepVersions` sets how many replaced versions stay for rollback.

## Sources

A source names where a tool comes from.

- `aqua:owner/repo` downloads a binary artifact from an aqua registry definition and checks the upstream checksum the definition declares.
- `release:github/owner/repo` or `release:gitlab/owner/repo` downloads a forge release asset, chosen from the release's file names.
- `apt:package` installs a Debian package. It needs a Debian-based image and root.
- `npm:pkg`, `pip:pkg`, `cargo:crate` and `go:<package path>` install through each language's package tool. `pip:` uses uv.
- `manual` runs a bash install script you write.

A language source is a tool too. An `npm:` install adds `node` from the catalog, `pip:` adds `uv`, `cargo:` adds `rust`, and `go:` adds the Go toolchain.

A `go:` entry names the package `go install` builds, such as `golang.org/x/tools/gopls`. Its latest version comes from the Go module proxy's version list for the module that contains the package, leaving out retracted versions. Only a module with no tagged version, whose list is empty, is read from the proxy's `@latest` instead, which then names a pseudo-version of its newest commit. A `+incompatible` version counts only when the module's highest compatible version has no `go.mod` of its own, as with the go command. When every listed version is retracted, the lookup fails, as `go install <package>@latest` does. The engine asks about each path from the package's own up to its first element, longest first, and refuses a package path with more than 16 elements before asking about any of them. It also refuses a package path of 4096 bytes or more, which `go install` cannot build because Linux refuses a file path that long.

uv builds each `pip:` tool on a Python interpreter it downloads into `python/interpreters` under `ToolsDir`, never on a Python found on `PATH`. An entry's `python` field, such as `3.14`, asks for a version, for a package whose wheels do not yet support the newest Python. Without it, uv takes the newest interpreter already in that directory, or downloads the newest. Every install names the interpreter to uv, so removing an entry's `python` moves its venv to the newest one at the next install. A `pip:` tool whose venv runs on an interpreter outside that directory, such as one built by an older engine, counts as not installed, and its next install builds a new venv there, replacing the old one only once uv has resolved the new one, so a rebuild uv cannot resolve, such as one whose version PyPI no longer serves, leaves the tool as it was.

Where a source lists several versions, the engine takes the highest release and skips prereleases, unless the recorded version is itself a prerelease. When a list holds only prereleases, a tool not recorded at a prerelease has no latest version, and the lookup fails saying so. A pseudo-version counts as a prerelease, so a Go module with no tagged version is such a list. A tag that is only a date, such as `2025-01-06` or `v2025-01-06`, counts as a release; a dated tag with a word before it, such as `nightly-2025-01-06`, counts as a prerelease. The node and go release indexes, GitHub tag lists, GitLab releases and the Go module proxy are read this way. The engine reads every page of a GitHub tag list or GitLab release list, up to 20 pages of 100; a longer list fails the lookup, because the forges do not order it by version and the highest could sit on a page not read. npm, PyPI, crates.io, apt and GitHub's latest release name one version, and the engine takes it. One lookup, every request and retry included, gives up after 2 minutes; apt lookups run local commands, and their index refresh keeps its own 3-minute limit.

## Dependencies

A tool's dependencies are installed whenever the tool is. Installing a tool adds every dependency the catalog names, enables any that is a template, and installs the whole set with the dependencies first. The job log names each entry it enabled and which tool asked for it. When one dependency cannot be resolved, the tool that needs it fails with `dependency "<name>" failed` and the reason. That attempt adds no dependency and enables no template, and the tools in the same job that do not need it still install.

Debian packages from `apt:` entries install before the other tools in the job, because a Go, Rust, Python or Node tool may compile against one it does not list as a dependency.

Enabling a tool you name yourself stays explicit. `Install` on a template returns `ErrDisabled`, which the REST handler sends as `409 disabled`, because enabling changes the user's intent, and only a dependency enables a tool on its own.

Each inventory row reports its `dependents`, the enabled entries that need it through `requires` or as the runtime of their source, directly or through another enabled entry. A client reads it to ask the user before sending a disable or remove the engine would refuse, and a forced one takes that whole set. It is advisory, because the engine works the set out again under the manifest lock, so a request based on a stale inventory is still refused.

## Essential tools

A catalog overlay can mark a tool `essential`. That is your product saying a feature stops working without the binary, which registry data can never say. The engine reads the flag from the live catalog when a removal is requested and refuses it with `ErrEssential`, or `409 essential` over HTTP. `force` does not override it, and a cascade whose dependents include an essential tool is refused whole.

Disabling an essential tool still works. It uninstalls the files and keeps the entry. `Inventory` reports the flag on each row, so a client can hide a delete button the engine would refuse.

## Engine calls

- `New(cfg *Config) (*Engine, error)` starts an engine. It writes the seed manifest when none exists and starts the job worker. It also writes and removes a test file in `ConfigDir` before the worker starts. When that write fails, or when the filesystem widens the file's mode, for example through an inherited ACL, `New` returns an error naming the directory. When only the cleanup of that file fails, it logs a warning and starts. `Close()` stops the catalog schedule and the worker, cancels the running job and returns once they have stopped.
- `Inventory() (*Inventory, error)` returns every manifest entry joined with its install state, the system group from `Config.System`, the Debian packages present with no manifest entry, and the active job.
- `Search(q string) []CatalogEntry` searches the catalog and hides names already in the manifest. An empty query returns the catalog entries marked `featured`, sorted by name.
- `SearchWithCounts(q string) SearchCounts` answers one query from the catalog, the uninstallable entries and the Debian package index at once. `Search`, `SearchUnavailable` and `SearchApt` each return one part of it. Each part carries its match count before the cut, and `AptState` says whether the Debian index is `unavailable`, `indexing` or `available`. That lets a client say "still indexing" rather than reporting a package as missing. `SearchApt`'s own bool treats the first two as one.
- `Add(ctx, *AddRequest) (*Job, error)` records a new tool and starts its install. With `Disabled: true` it adds a template instead, starts no job and returns a nil job.
- `Patch(name, PatchRequest) (*Job, error)` merges any of `Version`, `Pin`, `Disabled`, `Description`, `Requires`, `Install`, `Uninstall`, `Python` and `VersionArgs` into an entry. Setting `Disabled` to true uninstalls the tool and keeps the template, and setting it to false installs it. A version or `Python` change on an enabled entry starts a reinstall, and so does a `Pin` change on an enabled `apt:` entry, to set its hold. A `Requires` change on an enabled entry that names a tool with no enabled entry starts an install, which adds or enables that tool. A `VersionArgs` change starts no job and applies at the next install check. `Force` allows disabling a tool that enabled entries need, and disables every enabled entry that needs it, directly or through another one, so Reconcile does not enable it again.
- `Install(name) (*Job, error)` retries an existing, enabled entry. It refuses a template with `ErrDisabled`.
- `Update(names ...string) (*Job, error)` updates every unpinned, enabled entry, or only the named ones. A version check that fails is skipped, except one GitHub refused for a rate limit. That fails the job once the other entries are checked and updated.
- `Remove(name) (*Job, []string, error)` uninstalls a tool and deletes its entry. A tool that enabled entries need is refused, and the call returns their names. `RemoveWithDependents(name)` removes those entries too, and every enabled entry that needs one of them, so no enabled entry is left needing a removed tool for Reconcile to add back. The refusal, and each inventory row's `Dependents`, name that whole set.
- `Reconcile(mode) (*Job, bool, error)` brings the disk in line with the manifest. `ReconcileMissing` installs missing enabled entries, reinstalls an entry the engine installed at another version than the manifest now names or a pinned `apt:` entry dpkg reports at another version, rebuilds a `pip:` entry whose venv was built for another `python` request, installs the dependencies of an enabled entry that have no enabled entry, and theirs, enabling a template rather than uninstalling it, sets each `apt:` entry's dpkg hold to its pin and uninstalls disabled entries the engine owns that none of those installs needs, with no network traffic when nothing has changed. `ReconcileFull` also starts an update pass. The bool reports whether a job was started. It is false, with a nil job and a nil error, when the manifest is empty and no tool is installed.
- `Wait(ctx, jobID) (*Job, error)` blocks until a job finishes and returns the moment it does. A waiter keeps its job's result however many jobs finish meanwhile, and a job that has already finished is returned even when `ctx` is done. Only a Wait that starts after its job finished, once the job has dropped out of the retained history of finished jobs, returns `ErrUnknownJob`, as does an id that was never enqueued.
- `EnsureInstalled(ctx, name) error` is for a product action that needs a binary now. It creates the entry from the catalog, enables a template, installs it and its dependencies, or reinstalls it or a dependency when `Reconcile` would, and waits.
- `Jobs() (active *Job, recent []*Job)` and `CancelJob(id) bool` show the queue and cancel a job.
- `RefreshCatalog() (*Job, error)` starts a catalog refresh, and returns `ErrRefreshNotConfigured` when `Config.Refresh` is unset. `CatalogInfo() CatalogInfo` describes the live catalog. [The catalog](catalog.md) has both.

A call that starts a job returns `ErrQueueFull` when 8 jobs already wait, and `ErrShuttingDown` once `Close` has begun. A reconcile is never refused for a full queue, because one queued reconcile covers every later request. An `Add`, `Patch` or `Remove` whose job is refused does not write the manifest, so every field and every cascaded dependent stay as they were, and an edit another call makes meanwhile is never undone.

`*DependentsError` carries the names behind `ErrHasDependents` for `errors.As`, `*RootIntegrityError` carries every path behind `ErrRootIntegrity`, and `*GitHubRateLimitError` carries the detail behind `ErrGitHubRateLimited`. The result types `Inventory`, `ToolInfo`, `SystemTool` and `Job` are also what the REST handler sends.

The other types are `Tool` and `Manifest` for the manifest, `ToolStatus` and `State` for the install state, and `Catalog` and `CatalogEntry`, checked with `VerifyCatalog`, for the catalog. `SearchCounts` and `AptState` shape a search. `CancelCause` is `CancelShutdown`, `CancelCaller` or its zero value `CancelUnknown`.

## Jobs

Every change runs as a job on one queue, one job at a time. The queue holds up to 8 waiting jobs and refuses more, so a bulk install sends one job, waits for it, then sends the next. A job may run for 30 minutes, keeps its last 500 output lines, and the queue remembers the last 10 finished jobs.

`Config.OnJobChanged` receives every state change, and `Config.OnJobOutput` receives output lines in batches about every 150 ms. Neither callback may block.

A failed job carries its message in `error`, and `Job.Err()` returns the error behind it for `errors.As`. When a command fails, the error carries up to the last 500 bytes of the command's output. The job output of an install command keeps every line. When a GitHub rate limit failed the job, `error_code` is `github_rate_limited`. Its `rate_limit` field says whether the request carried a token, when the limit resets and what hourly limit GitHub reported. Your app decides what to tell the user, for example to set a token when `authenticated` is false.

The engine does not retry a rate-limited request or wait for the reset. Until the limit resets, and for at least one minute, the engine sends no more GitHub API requests with the same token. Each one fails at once with the same error. Requests with no token are held back the same way. Requests with a different token are sent as usual, so a token your app sets after an anonymous limit takes effect at once.

A cancelled job carries `cancel_cause`. It is `shutdown` when `Close` stopped it, including the running job's cancelled context, and `caller` when `CancelJob` or the cancel route stopped it. The field is left out when a cancellation names no cause, so an unknown cause never reads as a shutdown. A shutdown cancel is routine and need not alert. A caller cancel is deliberate.

## Debian packages

An `apt:` entry is manifest intent like any other and installs a Debian package. Removing an `apt:` entry stops the engine installing the package and leaves the package in place, because packages are shared and the engine cannot prove nothing else needs one. An `apt:` entry's pin is also its package's dpkg hold, so apt does not move a pinned package as another package's dependency. Every install of an `apt:` entry ends by holding its package when the entry is pinned and releasing the hold when it is not, and a pin change starts that install, which skips `apt-get` when the package is already installed at the entry's version. An install lifts the hold on its own package for `apt-get`, even when the package is held but not installed, and restores it afterwards, failed or not, so other held packages stay fixed. A failed `apt-mark`, or a `dpkg-query` failure other than an unknown package, fails the job, and `Reconcile` installs any entry whose hold differs from its pin, so a recreated container or a hand-run `apt-mark` is put right. An unpinned entry installs apt's candidate, and the entry and the install state take the version dpkg then reports, because the version an entry records is the candidate apt offered when it was last checked. A pinned entry installs exactly its version, with `--allow-downgrades` when the package is installed at another one, fails when apt cannot install that version, and counts as installed only while dpkg reports it, so `Reconcile` puts back a pinned package that moved. Removing a pinned `apt:` entry while no install of it runs leaves its hold with the package. Removing it after its install has lifted the hold for `apt-get` leaves the package unheld, because the job finds no entry and adds no hold. A package installed for several architectures is read, held and released as its native-architecture instance, the one `apt-get` and `apt-mark` act on for a bare name, so a package installed only for a foreign architecture counts as not installed. The engine never changes another architecture's selection: when `apt-get` fails while dpkg holds an installed copy of the package for another architecture, the job's error names that copy and the `apt-mark unhold` that releases it, and `Reconcile` retries the entry at each pass until it installs. apt and dpkg run under the C locale, so the engine reads their answers whatever the server's locale, and their output in a job's log is in English.

`Inventory` lists the Debian packages on the host that no entry owns, leaving out the ones apt installed automatically and Debian's required and important packages.

## One engine per data directory

The manifest's single-writer guarantee is a lock inside one process. Run one engine per data directory. Any other process, such as a CLI or an agent, goes through your server.
