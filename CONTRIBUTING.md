# Contributing to toolbelt

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Rules

- Engines of any version may read the catalog [tool-catalog](https://github.com/cplieger/tool-catalog) publishes, from an image or a runtime fetch. A format change may add a field or top-level key. Renaming, removing or redefining one makes older engines misread or refuse the catalog.
- Only `cmd/toolcatalog` imports the TOML and YAML parsers. Keep them out of the root and `httpapi` packages, even though `go.mod` lists both. An import there adds them to every consumer's build.
- An engine call that writes the manifest and queues a job for it reserves the job inside `MutateManifest` and publishes it after the write, through `commitJob`, as `Add`, `Patch` and `Remove` do. A queue refusal then aborts the write, so the manifest never records a state no job will bring about and there is no undo write to erase another call's edit, and the worker never starts the job against the old manifest. Never undo a manifest write after the fact.
- An `apt:` row's dpkg hold is set only by `holdToPin`, the last step of every job that installs the row, which reads the pin from the manifest as it stands then. A pin change queues such a job, and `Reconcile` counts a hold that differs from the pin as not converged. An `apt-mark` call anywhere else, or one fed a pin read earlier, can finish after a later pin's job, and dpkg's hold then disagrees with the manifest.
- A version source that lists several versions picks through `latestTag`, or `highestModuleVersion` for the Go module proxy, which skip prereleases unless the recorded version is one. A highest-version comparison of its own would offer a prerelease such as `v27.0.0-alpha.0` as every user's update.
- A cached answer is keyed on every input that decides it: a probe verdict on the declared `version_args`, the probed file's identity and a `pip:` tool's resolved interpreter's identity (`fileIdentity`: device, inode and ctime besides path, mode, size and mtime, since a replacement can keep those four), a latest version on the prerelease line and the aqua definition's `type`, `version_source`, `version_filter` and `version_prefix`. A missing key part keeps serving the old answer after that input changes.
- A directory under `ToolsDir` that holds code the engine runs joins `managedDirs`, and the install that writes into it creates it with `ensureManagedDirs`. A directory left out is neither created owner-writable nor judged by `VerifyRootIntegrity`.
- A new sentinel error that an `httpapi` route returns needs a case in `writeEngineError`, or the route answers 400 `bad_request`. Add it under "Replies and refusals" in `docs/http-api.md` and to the README's API list too.
- `converged` compares every manifest input an install decides on with the state record or the live check: the version, `python`, the dependency edges and an `apt:` row's pin, its version when pinned, and dpkg's version against the record a failed install left. A new install-deciding field needs a `Patch` transition, a `converged` comparison and a red `Reconcile` test, or `Reconcile` reports converged while the manifest asks for something else.

## Checks

This repo has no tests for `cmd/toolcatalog`, so CI never compiles a catalog.

After you change the compiler or the catalog types it shares with the engine, run the tool-catalog dry run on your working tree. From a [tool-catalog](https://github.com/cplieger/tool-catalog) checkout next to this one:

```sh
TOOLCATALOG_VERSION=v3.0.0 TOOLCATALOG_RUN='go run -C ../toolbelt ./cmd/toolcatalog' DRY_RUN=1 bash scripts/publish.sh
```

It downloads the pinned mise and aqua registries, compiles them, checks the engine's required tools and writes `./tool-catalog.json`. `TOOLCATALOG_VERSION` only labels the result. It needs `curl`, `jq` and `tar`.

## Releases

`cmd/toolcatalog` releases with the module under the same tag, and its commits take the `toolcatalog` scope, as in `fix(toolcatalog):`. A compiler change reaches the published catalog only once tool-catalog's pinned `TOOLCATALOG_VERSION` moves to that tag.
