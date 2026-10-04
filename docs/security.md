# Security

This page describes what the engine checks before it installs or runs a tool, and what it trusts. It is for a developer deciding how to deploy a server that embeds toolbelt.

## Checksums

An `aqua:` artifact is checked against the checksum source its registry definition declares, such as an upstream `checksums.txt`. When a declared checksum cannot be fetched, read or matched, the install is refused, and there is no fallback to an unverified install. Only a definition that declares no checksum, or whose upstream turned checksums off, installs unverified. The engine logs a warning and records `"checksum": "unverified"` in `tools-state.json`.

A `release:` install checks the release's own checksum file when the release publishes one. A release without one installs unverified, and its state says so.

## Install checks

The engine checks an install by running it, not by looking for the file. The recorded binaries must exist and the tool must answer when run. With `version_args`, the answer must carry the recorded version. A binary that is cut short, built for the wrong architecture or at the wrong version counts as not installed and is installed again. A recorded binary that cannot be run at all falls back to a presence check, with a warning.

The same check runs as the last step of an install. A binary the system refuses to start fails the install rather than being recorded at its version. Exit status 127 counts as such a refusal, and the loader's own message goes into the recorded error, so it names a missing library. Any other non-zero exit is still an answer, because a tool that does not understand `--version` has still shown it can run. The check runs after the state is recorded and before old versions are pruned, so a failed check leaves the previous version in place.

## Writing to disk

Every extracted file and the staging directory are flushed to disk before the rename that publishes a version. The parent directory is flushed after it, and the state file before any replaced version is pruned. A flush failure, a full disk included, fails the install and leaves the previous version live.

Downloads are capped at 1 GiB. Archive extraction refuses a symlink that points outside the install tree. Installs land in versioned directories that are swapped in one step.

## Network

Every fetch goes through a client that allows only public IP addresses, checked when the connection is made, and only port 443, with its own redirect policy. Transient failures are retried and rate limits are respected through [cplieger/httpx](https://github.com/cplieger/httpx).

Requests to the GitHub API carry the token that `gh auth token` reports, when the GitHub CLI is installed and logged in. That token is sent to `api.github.com` only, never to a download host. Without it, GitHub allows 60 API requests an hour per IP address. When that limit runs out, the error gives the time it resets. The latest `node` and `go` versions come from nodejs.org and go.dev, so those two need no GitHub request.

## The manual source

A `manual` entry runs a bash script by design. It is an escape hatch for a volume with one user, and it carries the same trust as editing the manifest.

## Binaries the engine runs

The engine starts system binaries by absolute path from `/usr/bin` and `/bin`, never through `PATH`. They are `tar`, `unzip`, `gunzip`, `bzip2`, `xz` and `zstd` for archives, `bash` for `manual` scripts, and `apt-get`, `apt-cache`, `apt-mark` and `dpkg-query` for `apt:` entries. A missing one fails the install that needs it.

This matters because the engine's own `bin/` comes before the system directories on `PATH` and lives on the volume. A `PATH` lookup would let a file written there replace those binaries on paths the engine runs with no user present, and as root for the apt binaries.

The protection is limited. If your server runs as root, it can still replace files in the system directories, which belong to root, so a fixed path is not unforgeable. What changes is persistence. A file placed in the system directories disappears with the container, while one placed in the tools tree stays on the volume and runs again each time your server calls `Reconcile` at startup.

The apt binaries get the trusted directories added in front of the `PATH` they inherit, so a Debian maintainer script can still rely on `/usr/sbin`. The archive tools get the trusted directories alone. A `manual` script keeps the tools tree first, because reaching the installed tools is what it is for.

## Binaries the engine installs

A binary the engine installs itself, such as `gh`, `npm`, `uv`, `cargo` or `go`, is still found through the tools tree. Publishing it there is the point, and an absolute path would name the same writable file.

`VerifyRootIntegrity` limits which other accounts can reach that tree, as [Configuration](configuration.md#root-integrity-check) describes. It cannot separate the engine from a shell command running beside it as the same user. On a volume where someone else holds a shell as that user, those binaries are theirs to replace. The engine is built for a volume with one user.
