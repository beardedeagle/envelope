# Operational notes

Changing an encrypted env file changes the wrapper path ⇒ `switch`
restarts the unit. Changing an out-of-store keyfile does not touch the unit
file ⇒ `systemctl restart` after rotation (strategy-B store blobs *do*
trigger restarts). `pkgs.dotenvx` is `buildNpmPackage` and drags Node into
the closure; the module is package-agnostic if you repackage upstream's
standalone binary. The wrapper additionally depends on `jq` (trivial).
Env-file keys literally starting with `DOTENV_` are filtered at injection
(dotenvx metadata). A warning fires if a staged filename breaks the
`.env*` convention, since private-key selection hangs off it.

Swapping the CLI: `package` may point at any implementation whose `get`
supports repeated `-f`, `--env-keys-file`, `--strict`, `--overload`, and
`--format json`. The Rust
[dotenvx-rs](https://github.com/linux-china/dotenvx-rs) (with those flags
patched in) drops Node from every consumer closure, execs in
microseconds, and performs **no** `$(…)`/`''${VAR}` interpolation inside
values — closing the contributor-controlled command-execution footgun in
`env`/`files` modes outright.

Credentials mode: an env-file change changes postmaster's config store
path ⇒ `switch` restarts the daemon; consumers pick up new values on
*their* next (re)start, since credentials are fetched once at process
invocation. Rotation of the daemon's out-of-store keys file needs
`systemctl restart dotenvx-credd` — or nothing at all if you sealed with
`daemon.key.encryptedFile`, whose store path changes ⇒ auto-restart. The
consumer's runtime closure carries no Node in this mode; `pkgs.dotenvx`
remains host-side tooling. Current dotenvx writes `.env.keys` values
unquoted; postmaster's parser accepts both quoted and unquoted forms.
Toolchain floor: the crate is edition 2024 and the lock pins `zeroize 1.9`
(an edition-2024 manifest), so building needs cargo/rustc ≥ 1.85 —
satisfied by nixos-25.05's `rustPlatform`, but not by older pinned
toolchains.

macOS: the `dotenvx-ramdisk` launchd job mounts the HFS RAM disk
(`services.dotenvx.ramdisk.mountPoint`, default `/private/var/run/dotenvx`,
`sizeMB` default 16) at boot and pre-creates one owner-only dir per
non-`env` service; both it and `dotenvx-credd` use `KeepAlive` so a consumer
that starts before the substrate is up simply retries. `key.file` on darwin
must be readable by each consumer's `UserName` (there is no `LoadCredential`
hand-off), so use per-service key files or group-readable perms rather than
`0400 root` when services run as non-root users. `key.keychainService`
sidesteps the filesystem entirely — keys live as generic-password items in
the System keychain (see the option's provisioning snippet); it requires a
dotenvx CLI implementing `--env-keys-keychain` (dotenvx-rs).

Debugging on a host:

```console
$ sudo dotenvx get -f /nix/store/…-dotenvx-env-myapp/.env.production \
    -fk /var/lib/dotenvx/.env.keys --format json
```

(`systemctl cat myapp` shows the wrapper, which shows the store path.)
