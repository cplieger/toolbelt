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
- `npm:pkg`, `pip:pkg`, `cargo:crate` and `go:module` install through each language's package tool. `pip:` uses uv.
- `manual` runs a bash install script you write.

A language source is a tool too. An `npm:` install adds `node` from the catalog, `pip:` adds `uv`, `cargo:` adds `rust`, and `go:` adds the Go toolchain.

## Dependencies

A tool's dependencies are installed whenever the tool is. Installing a tool adds every dependency the catalog names, enables any that is a template, and installs the whole set with the dependencies first. The job log names each entry it enabled and which tool asked for it. When one dependency cannot be resolved, the tool that needs it fails with `dependency "<name>" failed` and the reason. That attempt adds no dependency and enables no template, and the tools in the same job that do not need it still install.

Enabling a tool you name yourself stays explicit. `Install` on a template returns `ErrDisabled`, which the REST handler sends as `409 disabled`, because enabling changes the user's intent, and only a dependency enables a tool on its own.

Each inventory row reports its `dependents`, the enabled entries that need it through `requires` or as the runtime of their source. A client reads it to ask the user before sending a disable the engine would refuse. It is advisory, because the engine works the set out again under the manifest lock, so a request based on a stale inventory is still refused.

## Essential tools

A catalog overlay can mark a tool `essential`. That is your product saying a feature stops working without the binary, which registry data can never say. The engine reads the flag from the live catalog when a removal is requested and refuses it with `ErrEssential`, or `409 essential` over HTTP. `force` does not override it, and a cascade whose dependents include an essential tool is refused whole.

Disabling an essential tool still works. It uninstalls the files and keeps the entry. `Inventory` reports the flag on each row, so a client can hide a delete button the engine would refuse.

## Engine calls

- `New(cfg *Config) (*Engine, error)` starts an engine. It writes the seed manifest when none exists and starts the job worker. It also writes and removes a test file in `ConfigDir` before the worker starts. When that write fails, or when the filesystem widens the file's mode, for example through an inherited ACL, `New` returns an error naming the directory. When only the cleanup of that file fails, it logs a warning and starts. `Close()` stops the catalog schedule and the worker, cancels the running job and returns once they have stopped.
- `Inventory() (*Inventory, error)` returns every manifest entry joined with its install state, the system group from `Config.System`, the Debian packages present with no manifest entry, and the active job.
- `Search(q string) []CatalogEntry` searches the catalog and hides names already in the manifest. An empty query returns the catalog entries marked `featured`, sorted by name.
- `SearchWithCounts(q string) SearchCounts` answers one query from the catalog, the uninstallable entries and the Debian package index at once. `Search`, `SearchUnavailable` and `SearchApt` each return one part of it. Each part carries its match count before the cut, and `AptState` says whether the Debian index is `unavailable`, `indexing` or `available`. That lets a client say "still indexing" rather than reporting a package as missing. `SearchApt`'s own bool treats the first two as one.
- `Add(ctx, *AddRequest) (*Job, error)` records a new tool and starts its install. With `Disabled: true` it adds a template instead, starts no job and returns a nil job.
- `Patch(name, PatchRequest) (*Job, error)` merges fields into an entry. Setting `Disabled` to true uninstalls the tool and keeps the template, and setting it to false installs it. A version change starts a reinstall. `Force` allows disabling a tool that enabled entries need, and disables those entries too, one level deep.
- `Install(name) (*Job, error)` retries an existing, enabled entry. It refuses a template with `ErrDisabled`.
- `Update(names ...string) (*Job, error)` updates every unpinned, enabled entry, or only the named ones. A version check that fails is skipped, except one GitHub refused for a rate limit. That fails the job once the other entries are checked and updated.
- `Remove(name) (*Job, []string, error)` uninstalls a tool and deletes its entry. A tool that enabled entries need is refused, and the call returns their names. `RemoveWithDependents(name)` removes those entries too. The cascade is one level deep, the tools that need the named one directly, so a longer chain leaves its outer tool depending on a tool that is gone.
- `Reconcile(mode) (*Job, bool, error)` brings the disk in line with the manifest. `ReconcileMissing` installs missing enabled entries and uninstalls disabled ones the engine owns, with no network traffic when nothing has changed. `ReconcileFull` also starts an update pass. The bool reports whether a job was started. It is false, with a nil job and a nil error, when the manifest is empty and no tool is installed.
- `Wait(ctx, jobID) (*Job, error)` blocks until a job finishes. A job id the queue no longer holds returns `ErrUnknownJob`.
- `EnsureInstalled(ctx, name) error` is for a product action that needs a binary now. It creates the entry from the catalog, enables a template, installs it and waits.
- `Jobs() (active *Job, recent []*Job)` and `CancelJob(id) bool` show the queue and cancel a job.
- `RefreshCatalog() (*Job, error)` starts a catalog refresh, and returns `ErrRefreshNotConfigured` when `Config.Refresh` is unset. `CatalogInfo() CatalogInfo` describes the live catalog. [The catalog](catalog.md) has both.

`*DependentsError` carries the names behind `ErrHasDependents` for `errors.As`, `*RootIntegrityError` carries every path behind `ErrRootIntegrity`, and `*GitHubRateLimitError` carries the detail behind `ErrGitHubRateLimited`. The result types `Inventory`, `ToolInfo`, `SystemTool` and `Job` are also what the REST handler sends.

The other types are `Tool` and `Manifest` for the manifest, `ToolStatus` and `State` for the install state, and `Catalog` and `CatalogEntry`, checked with `VerifyCatalog`, for the catalog. `SearchCounts` and `AptState` shape a search. `CancelCause` is `CancelShutdown`, `CancelCaller` or its zero value `CancelUnknown`.

## Jobs

Every change runs as a job on one queue, one job at a time. The queue holds up to 8 waiting jobs and refuses more, so a bulk install sends one job, waits for it, then sends the next. A job may run for 30 minutes, keeps its last 500 output lines, and the queue remembers the last 10 finished jobs.

`Config.OnJobChanged` receives every state change, and `Config.OnJobOutput` receives output lines in batches about every 150 ms. Neither callback may block.

A failed job carries its message in `error`, and `Job.Err()` returns the error behind it for `errors.As`. When a GitHub rate limit failed the job, `error_code` is `github_rate_limited`. Its `rate_limit` field says whether the request carried a token, when the limit resets and what hourly limit GitHub reported. Your app decides what to tell the user, for example to set a token when `authenticated` is false.

The engine does not retry a rate-limited request or wait for the reset. Until the limit resets, and for at least one minute, the engine sends no more GitHub API requests with the same token. Each one fails at once with the same error. Requests with no token are held back the same way. Requests with a different token are sent as usual, so a token your app sets after an anonymous limit takes effect at once.

A cancelled job carries `cancel_cause`. It is `shutdown` when `Close` stopped it, including the running job's cancelled context, and `caller` when `CancelJob` or the cancel route stopped it. The field is left out when a cancellation names no cause, so an unknown cause never reads as a shutdown. A shutdown cancel is routine and need not alert. A caller cancel is deliberate.

## Debian packages

An `apt:` entry is manifest intent like any other and installs a Debian package. Removing an `apt:` entry stops the engine installing the package and leaves the package in place, because packages are shared and the engine cannot prove nothing else needs one. Pinning an `apt:` entry also holds the package with `apt-mark`, so apt does not move it as another package's dependency.

`Inventory` lists the Debian packages on the host that no entry owns, leaving out the ones apt installed automatically and Debian's required and important packages.

## One engine per data directory

The manifest's single-writer guarantee is a lock inside one process. Run one engine per data directory. Any other process, such as a CLI or an agent, goes through your server.
