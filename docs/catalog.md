# The catalog

This page covers what the catalog holds, how the engine refreshes it while running, and the `toolcatalog` command that compiles and checks it. It is for a developer who bakes a catalog into an image or points the engine at a published one.

## What it holds

The catalog is one JSON file that tells the engine how to install each tool by name. For each tool it holds the source, download templates, checksum location and dependencies. The published catalog holds about 900 tools that run on Linux, compiled from the mise and aqua registries. It also lists the tools it knows and cannot install, each with the reason, so a search can say why a tool is missing. It carries both registries' MIT license texts and a `generated` timestamp.

## Runtime refresh

The catalog changes on its own schedule, separate from your image. With `Config.Refresh` set, the engine fetches the published catalog at the configured interval, and on demand through `RefreshCatalog` or the REST handler's refresh route.

The engine never fetches at construction. Call `RefreshCatalog` once your boot work is queued, so the refresh does not run ahead of it.

Each fetched catalog goes through these steps before it is used:

1. It must hold at least 400 entries and resolve every name in `Refresh.Require`, the same offline checks as `toolcatalog verify`.
2. Your `Config.CatalogOverlays` are applied to it again.
3. The fetched file is saved under `ConfigDir` as `tool-catalog.cached.json`.
4. It replaces the live catalog in one step.

On any failure the last good catalog stays, so a bad fetch changes nothing. One fetch, retries included, is limited to 2 minutes and 16 MiB. At the next start, the engine loads whichever of the cached and the baked catalog has the newer `generated` timestamp.

`CatalogInfo()` reports the registry refs, the `generated` timestamp, the entry count, the last refresh error and whether a schedule runs. Its source field says where the live catalog came from, which is `baked`, `cached`, `remote` or `none`.

## The toolcatalog command

`cmd/toolcatalog` compiles a catalog and checks it against a list of required tools. It versions with the engine in one module. A catalog is therefore always compiled under the schema and checks of the engine release that reads it. [tool-catalog](https://github.com/cplieger/tool-catalog) runs it on every registry release and publishes the file that `DefaultCatalogURL` points at. An image can run `verify` against its own required list at build time.

Importing the library does not pull the compiler's TOML and YAML parsers into your build or binary, thanks to Go's module graph pruning. They add a few lines to your `go.sum` only.

```sh
go run github.com/cplieger/toolbelt/v3/cmd/toolcatalog@latest \
    -mise mise-checkout/registry -aqua aqua-registry-checkout/pkgs \
    -overlay overlays.json -refs mise=<ref>,aqua=<ref> -out tool-catalog.json

go run github.com/cplieger/toolbelt/v3/cmd/toolcatalog@latest \
    verify -catalog tool-catalog.json -require required-tools.txt
```

Compiling requires `-mise <dir>` and `-aqua <dir>`. It also takes any number of `-overlay <file>`, plus `-refs k=v,...` and `-out <file>`, which defaults to `tool-catalog.json`. The compiler has no curated tool set of its own. Your bundled tools reach the catalog through `-overlay`, or at run time through `Config.CatalogOverlays`. It reads each registry's `LICENSE` from the directory above the one you name. It stops when one is missing, so the MIT notice travels with every copy.

`verify` takes `-catalog <file>`, `-require <file>` and any number of `-overlay <file>`, applied before the check. It exits non-zero when a required name is missing from the catalog. It also fails when an entry cannot install on Linux amd64 and arm64, for example with no source or a template it cannot read. Registry changes then show up when you publish or build an image, not in a boot job.

Overlays merge with `ApplyOverlay`, the same function the runtime refresh uses. Pin the command to the toolbelt version your server uses with `@vX.Y.Z`.
