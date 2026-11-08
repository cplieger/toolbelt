# Installing a pinned release with pin

The `pin` package installs one upstream release at a version and SHA-256 you pin, keeps it running across restarts and keeps the previous version as a fallback. This page is for a developer whose server must ship a binary it cannot bake into its image, such as a proprietary CLI, and run that binary as the server's own user.

`pin` is separate from the engine. A program that imports only `pin` links none of the engine's third-party modules.

## What a start does

`Manager.Ensure` runs these steps in order, and `EnsureWithRetry` repeats it with a backoff from 30 seconds, doubling up to 10 minutes, for `MaxAttempts` attempts, 4 by default.

1. It checks who can write the versions directory, `<Root>/<Name>-versions`, and every directory above it. Nothing on the volume is deleted or written before this check, and a tree it refuses is never changed.
2. It runs the one-shot `Purge` of a previous installer's layout and removes version directories an interrupted install left.
3. It picks the version to run. That is the pinned version when its directory is complete, else the most recently activated other complete version. Each candidate's binary must answer `ProbeArgs` with the version its directory claims.
4. When the pinned version is not usable, it installs it. The archive is downloaded to an unlinked file, its SHA-256 is checked against `Digests`, and it is unpacked from that same file. The staged binary must answer the probe with the pinned version and pass every `Required` assertion before the directory is renamed into place.
5. It runs every assertion against the selected binary, publishes the convenience link in `LinkDir` and removes old versions.

`Ready` is true only when a version is active and this process ran every `Required` assertion against that binary. An assertion's effect lives in the program's own settings, so a result remembered from an earlier start does not count. `Ready` returns a `Reason` when it is false, and the wording you show your users is yours.

`Rescan` repeats steps 1, 3 and 5 without downloading, so a version an operator restored by hand is picked up without a restart.

## Assertions

An `Assertion` is a command run against the binary with a 10-second limit, such as `settings app.disableAutoupdates true`. A failing `Required` assertion withholds readiness, and before publication it refuses the install. Any other assertion only logs a warning. `New` refuses a config with no `Required` assertion. Declare the setting that stops the program updating itself, or the cheapest command that must succeed against a working install.

## Who may write the tree

The check passes when only root, the user the process runs as and the users in `TrustedUIDs` can change the versions directory or any directory above it. It reads each directory's owner, mode and access-control list. A sticky directory above the tree, such as `/tmp`, is accepted, because the sticky bit stops other users renaming entries in it. The versions directory itself must not be sticky and writable by others, because anyone who can create an entry there can plant a complete-looking version.

No group can be trusted, because a group grant reaches every current and future member. Each entry in `TrustedUIDs` states that the user is already as privileged as your server. `ParseIdentities` reads such a list from an environment variable and returns how many entries it refused, never their text.

When the check refuses the tree, no version on it is activated. The purge, the sweep, the links, the pruning and the state file are all skipped, and the error names the directory and the writer. Each file in a version directory must also be private to the process, so an archive or a filesystem that leaves a file writable by others fails the install.

`Untrusted` is for a volume you know another host user can write. Only a version this process installed from a verified archive is activated, so every start downloads the archive again.

## Versions on disk

Each version lives in `<Root>/<Name>-versions/<version>/`, holding the binary and a `.complete` file written last. A directory without it is an interrupted install and is removed at the next start. `Version` returns the active version, `Path` the binary's absolute path, `PathEntry` its directory and `PathEnv` a `PATH` overlay that leads with it. Run `Path`, never the convenience link.

Retention keeps the active version and the most recently activated other version that would still be selected, so a bad pin falls back to the version that ran before it. A failed install removes nothing. Every activation sets its directory's modification time, which is the order retention reads.

The convenience link `<Root>/<LinkDir>/<Name>` points at the active binary for an operator using a shell. A link this manager published under another name, such as a sidecar an older release shipped, is removed. An entry another owner put in `LinkDir` is never replaced or removed. When you move `LinkDir`, list the old directories in `FormerLinkDirs`. Each activation that may write the tree removes the links this manager published there, so none is left pointing at a removed version, and leaves every other entry alone. A former directory that resolves to `LinkDir` through a symlink, in either direction, is skipped, so keeping the old name as a symlink to the new one is safe.

## Archives

The format comes from the extension of the URL `New` resolves: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2` or `.tbz`. The archive is unpacked with the engine's own unpacker, with the limits [Security](security-model.md#unpacking-archives) describes. Only the binary named `Name` under `ArtifactDir` is installed.

## Unsupported by design

- An archive whose release needs several binaries. `pin` installs the primary binary alone.
- Running an installer script from the archive.
- `.tar.xz` and `.tar.zst`, which need a system decompressor.
- Trusting a group, or installing into a tree another user can write.
