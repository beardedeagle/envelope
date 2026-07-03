# Injection modes

**`mode = "env"` (default).** Decrypted values are exported into the
process environment and the wrapper `exec`s your binary. Correct for
12-factor apps, with env's inherent exposure: readable via
`/proc/<pid>/environ` by root and the *same UID*, inherited by every child,
prone to appearing in crash dumps and debug output. `DynamicUser=true` makes
"same UID" mean "this service only". Note that dotenvx `get` interpolates
`$(…)`, `${VAR}`, and `$VAR` inside values itself (its documented feature),
*before* the wrapper's injection boundary — a repo contributor can write
`KEY=$(cmd)` and have `cmd` run at service start. For values from
semi-trusted contributors use `credentials` mode, which bypasses dotenvx
(and its interpolation) entirely and serves raw bytes — or a dotenvx CLI
that does not interpolate (see Operational notes on `dotenvx-rs`).

**`mode = "files"`.** Values are written one-file-per-key onto a
namespace-private tmpfs (`TemporaryFileSystem=/run/dotenvx`; on macOS, a
per-service directory on an HFS RAM disk) and only `<KEY>_FILE` pointer
variables are exported — the Docker-secrets convention
(`DATABASE_URL_FILE=/run/dotenvx/DATABASE_URL`) that many daemons support
natively. Secrets are absent from environ, `ps e`, crash-dump environment
sections, and ambient child inheritance; the mount is invisible outside the
unit's namespace (root needs `nsenter`) and is destroyed with the unit.
`DOTENVX_SECRETS_DIR` points at the directory. For a mostly-file-capable
app with a straggler:

```nix
services.dotenvx.services.myapp = {
  mode = "files";
  envPassthrough = [ "RUST_LOG" ];   # exported as a real env var anyway
  preventSwap = true;                # MemorySwapMax=0: tmpfs + heap never swap
};
```

`preventSwap` trades swap for OOM under memory pressure — deliberate,
opt-in.

**`mode = "credentials"`.** Real systemd credentials, served on demand by
the `postmaster` daemon (see its section below). The consumer's unit gets
`LoadCredential=<KEY>:/run/dotenvx-credd/<svc>/<KEY>.sock` per key and the
app reads `$CREDENTIALS_DIRECTORY/<KEY>` from unit-private, **unswappable**
ramfs. No dotenvx, Node, or jq anywhere in the consumer's start path; the
optional wrapper only exports non-secret `<KEY>_FILE` pointers. Strongest
hygiene of the three.
