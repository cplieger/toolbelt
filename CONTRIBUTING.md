# Contributing to toolbelt

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Rules

- Engines of any version may read the catalog [tool-catalog](https://github.com/cplieger/tool-catalog) publishes, from an image or a runtime fetch. A format change may add a field or top-level key. Renaming, removing or redefining one makes older engines misread or refuse the catalog.
- Only `cmd/toolcatalog` imports the TOML and YAML parsers. Keep them out of the root and `httpapi` packages, even though `go.mod` lists both. An import there adds them to every consumer's build.
- When the queue refuses a job, the engine call that wrote the manifest for it undoes the whole write, as `Add`, `Patch` and `Remove` do: every field it set and every row it cascaded to, leaving a field another call has changed since. Without the undo, the manifest records a state no job will bring about. A field added to `applyPatch` needs its line in `patchOutcome.revert`.
- A version source that lists several versions picks through `latestTag`, or `highestModuleVersion` for the Go module proxy, which skip prereleases unless the recorded version is one. A highest-version comparison of its own would offer a prerelease such as `v27.0.0-alpha.0` as every user's update.
- A new sentinel error that an `httpapi` route returns needs a case in `writeEngineError`, or the route answers 400 `bad_request`. Add it under "Replies and refusals" in `docs/http-api.md` and to the README's API list too.

## Checks

This repo has no tests for `cmd/toolcatalog`, so CI never compiles a catalog.

After you change the compiler or the catalog types it shares with the engine, run the tool-catalog dry run on your working tree. From a [tool-catalog](https://github.com/cplieger/tool-catalog) checkout next to this one:

```sh
TOOLCATALOG_VERSION=v3.0.0 TOOLCATALOG_RUN='go run -C ../toolbelt ./cmd/toolcatalog' DRY_RUN=1 bash scripts/publish.sh
```

It downloads the pinned mise and aqua registries, compiles them, checks the engine's required tools and writes `./tool-catalog.json`. `TOOLCATALOG_VERSION` only labels the result. It needs `curl`, `jq` and `tar`.

## Releases

`cmd/toolcatalog` releases with the module under the same tag, and its commits take the `toolcatalog` scope, as in `fix(toolcatalog):`. A compiler change reaches the published catalog only once tool-catalog's pinned `TOOLCATALOG_VERSION` moves to that tag.
