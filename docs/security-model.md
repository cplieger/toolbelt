# Security

This page describes what the engine checks before it installs or runs a tool, and what it trusts. It is for a developer deciding how to deploy a server that embeds toolbelt.

## Checksums

An `aqua:` artifact is checked against the checksum source its registry definition declares, such as an upstream `checksums.txt`. When a declared checksum cannot be fetched, read or matched, the install is refused, and there is no fallback to an unverified install. Only a definition that declares no checksum, or whose upstream turned checksums off, installs unverified. The engine logs a warning and records `"checksum": "unverified"` in `tools-state.json`.

A `release:` install checks the release's own checksum file when the release publishes one. A release without one installs unverified, and its state says so.

## Install checks

The engine checks an install by running it, not by looking for the file. The recorded binaries must exist, and an executable one must answer when run. With `version_args`, the answer must carry the recorded version. A binary that is cut short, built for the wrong architecture or at the wrong version counts as not installed and is installed again. A check's result is reused until the binary changes, and a replacement counts as a change even when it keeps the old file's size and modification time. A recorded binary that is present but not an executable file, such as a regular file without an execute bit, is not run: it counts as installed by its presence, and the engine logs a warning.

Two kinds of install have nothing to run. A Debian package counts as installed when dpkg reports it. An npm package that ships no binary, such as a shared config, counts as installed when the `package.json` npm installed for it carries the recorded version. A `pip:` tool is checked again whenever its Python interpreter's file changes, and one whose interpreter is gone, or lies outside `python/interpreters` under `ToolsDir`, counts as not installed and is installed again, though its launcher file has not changed.

The same check runs as the last step of an install, and an install that it does not count as installed fails, with the check's reason as the recorded error. A binary the system refuses to start is one such failure. Exit status 127 counts as a refusal, and the loader's own message goes into the error, so it names a missing library. Any other non-zero exit is still an answer, because a tool that does not understand `--version` has still shown it can run, but a tool that gives no answer within 10 seconds fails the install. A binary that answers its `version_args` with another version fails the install too, so an entry whose `version_args` do not print the version shows that as its error instead of being installed again at every reconcile. The check runs after the state is recorded and before old versions are pruned, so a failed check keeps the previous version on disk.

## Writing to disk

Every extracted file and the staging directory are flushed to disk before the rename that publishes a version. The parent directory is flushed after it, and the state file before any replaced version is pruned. A flush failure, a full disk included, fails the install and leaves the previous version live.

Downloads are capped at 1 GiB. Archive extraction refuses a symlink that points outside the install tree. Installs land in versioned directories that are swapped in one step.

After an install, the engine clears the group and other write bits from every directory and file it may have written and later runs: the tool's tree under `opt/`, the files in `bin/`, every package under `npm/lib/node_modules`, and every venv, interpreter and launcher under `python/`. npm, uv, go and tar create files through the umask, and on a volume whose ACL grants the group write access, such as ZFS with `nfs4acl`, every new file is group-writable whatever the umask. Symlinks are left alone, and a change the filesystem does not store fails the install. The managed directories themselves are created owner-writable only and are otherwise left as they are; [`VerifyRootIntegrity`](configuration.md#root-integrity-check) reports one another account can write.

The caches those builds reuse live in `cache/` under `ToolsDir`, whatever the server's `HOME` or environment says: the Go module and build caches (`GOPATH`, `GOMODCACHE`, `GOCACHE`), npm's and uv's caches and cargo's `CARGO_HOME`. A build takes a module, package or compiled output it finds there without fetching it again, so a cached file another account changed would change the next install. When `cache/` is missing, the engine creates it with mode 0700 at start and before each build, so no other account can reach it whatever the modes beneath, and `VerifyRootIntegrity` reports one that another account can enter. Because `CARGO_HOME` moves there, a setting in `~/.cargo/config.toml` applies only when the server's working directory is under `HOME` ([cargo's config lookup](https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure)); a `CARGO_*` environment variable always does.

## Network

Every fetch goes through a client that allows only public IP addresses, checked when the connection is made, and only port 443, with its own redirect policy. Transient failures are retried and rate limits are respected through [cplieger/httpx](https://github.com/cplieger/httpx).

Requests to the GitHub API carry the token that your `Config.GitHubToken` function returns. The engine asks for it on each request to `api.github.com` and sends it nowhere else, never to a download host, even one an API request redirects to.

The engine does not run the GitHub CLI or read `GH_TOKEN` or `GITHUB_TOKEN` to find a token. A login made with `gh auth login` does not reach the engine. To keep authenticated GitHub requests, set `Config.GitHubToken` to a function that returns your token.

Without a token, GitHub allows 60 API requests an hour per IP address, shared with everything else on that address. When a limit runs out, the request fails with `ErrGitHubRateLimited`. The error says whether the request carried a token and when the limit resets. [How toolbelt works](how-it-works.md#jobs) shows how a failed job reports it. The latest `node` and `go` versions come from nodejs.org and go.dev, so those two need no GitHub request.

## The manual source

A `manual` entry runs a bash script by design. It is an escape hatch for a volume with one user, and it carries the same trust as editing the manifest.

## Binaries the engine runs

The engine starts system binaries by absolute path from `/usr/bin` and `/bin`, never through `PATH`. They are `tar`, `unzip`, `gunzip`, `bzip2`, `xz` and `zstd` for archives, `bash` for `manual` scripts, and `apt-get`, `apt-cache`, `apt-mark` and `dpkg-query` for `apt:` entries. A missing one fails the install that needs it.

This matters because the engine's own `bin/` comes before the system directories on `PATH` and lives on the volume. A `PATH` lookup would let a file written there replace those binaries on paths the engine runs with no user present, and as root for the apt binaries.

The protection is limited. If your server runs as root, it can still replace files in the system directories, which belong to root, so a fixed path is not unforgeable. What changes is persistence. A file placed in the system directories disappears with the container, while one placed in the tools tree stays on the volume and runs again each time your server calls `Reconcile` at startup.

The apt binaries get the trusted directories added in front of the `PATH` they inherit, so a Debian maintainer script can still rely on `/usr/sbin`. The archive tools get the trusted directories alone. A `manual` script keeps the tools tree first, because reaching the installed tools is what it is for.

## Binaries the engine installs

A tool the engine installs and then runs itself, `npm`, `uv`, `cargo` or `go`, is still found through the tools tree. Publishing it there is the point, and an absolute path would name the same writable file.

`VerifyRootIntegrity` limits which other accounts can reach that tree, as [Configuration](configuration.md#root-integrity-check) describes. It cannot separate the engine from a shell command running beside it as the same user. On a volume where someone else holds a shell as that user, those binaries are theirs to replace. The engine is built for a volume with one user.
