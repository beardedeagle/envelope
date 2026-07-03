# envelope

Encrypted dotenvx `.env` files as first-class Nix deployment artifacts, for
**NixOS and nix-darwin** behind one shared option tree (`services.dotenvx`).
Includes the postmaster Rust credential daemon for `credentials` mode.

The trick that makes this compose: dotenvx ciphertext is *designed* to be
public. Every value is ECIES/secp256k1-encrypted individually, and the
`DOTENV_PUBLIC_KEY` embedded in the file only permits encrypting *new*
values. So the world-readable Nix store — normally the reason secrets and
Nix don't mix — stops being an adversary. Encrypted env files ship inside
the closure, deploy atomically, roll back with the generation, and the
entire secret surface collapses to one 64-hex private key per environment.

Runtime flow per service:

```
nix store: /nix/store/…-dotenvx-env-myapp/.env.production      (ciphertext)
systemd:   LoadCredential[Encrypted]= → $CREDENTIALS_DIRECTORY  (ramfs, unit-private)
ExecStart: wrapper → dotenvx get -f <store>/.env.production \
                       -fk $CREDENTIALS_DIRECTORY/dotenvx-myapp \
                       --strict --format json                    (transient)
           → inject (env vars, or files on a private tmpfs)
           → exec <your binary>                                  (MainPID = your binary)
```

Plaintext never touches persistent disk. dotenvx (Node) lives for
milliseconds at startup and exits before your service runs.

The diagram above is the systemd path; macOS runs the *same* wrappers under
launchd, with a RAM disk standing in for the private tmpfs and postmaster
self-binding its sockets. See [macOS (nix-darwin)](#macos-nix-darwin).

## Quick start

```nix
# flake.nix (system)
{
  inputs.envelope.url = "github:beardedeagle/envelope";
  outputs = { nixpkgs, envelope, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [ envelope.nixosModules.default ./configuration.nix ];
    };
  };
}
```

On macOS the module is `darwinModules.default` and the configuration is
identical (`nix-darwin.lib.darwinSystem { modules = [ envelope.darwinModules.default … ]; }`).

```nix
# configuration.nix (NixOS) — or darwin.nix (nix-darwin), same options
services.dotenvx = {
  enable = true;
  services.myapp = {
    envFiles  = [ ./secrets/.env.production ];   # encrypted; safe in repo + store
    execStart = "${pkgs.hello}/bin/hello --listen 127.0.0.1:8080";
    # key.file defaults to /var/lib/dotenvx/.env.keys (see provisioning)
  };
};

# The module only owns ExecStart + credentials. If the unit isn't defined
# by an upstream module, give it the basics yourself:
systemd.services.myapp = {
  wantedBy = [ "multi-user.target" ];
  serviceConfig.DynamicUser = true;   # own UID ⇒ own /proc environ boundary
};
```

Author secrets on your workstation as usual:

```console
$ dotenvx set DATABASE_URL 'postgres://…' -f secrets/.env.production
# commit secrets/.env.production; NEVER commit secrets/.env.keys
```

To compose ExecStart yourself (`execStart = null`):

```nix
systemd.services.myapp.serviceConfig.ExecStart = lib.mkForce
  "${config.services.dotenvx.wrappers.myapp} ${lib.getExe pkgs.hello} --transport stdio";
```

## Injection modes

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

## Key provisioning

**A. Manual keyfile (default).** One-time per host:

```console
$ sudo install -d -m 0700 /var/lib/dotenvx
$ sudo install -m 0400 /dev/stdin /var/lib/dotenvx/.env.keys <<'EOF'
DOTENV_PRIVATE_KEY_PRODUCTION="<64-hex from your local .env.keys>"
EOF
```

systemd treats an absolute-path credential as mandatory: missing file ⇒
unit fails to start. Fail-closed.

**B. TPM2/host-sealed blob — fully declarative key delivery.**

```console
# on the target host, once (--name MUST match dotenvx-<service>)
$ sudo systemd-creds encrypt --with-key=host+tpm2 \
    --name=dotenvx-myapp - myapp-myhost.cred <<'EOF'
DOTENV_PRIVATE_KEY_PRODUCTION="<64-hex>"
EOF
# copy myapp-myhost.cred back into the repo
```

```nix
services.dotenvx.services.myapp.key.encryptedFile =
  ./secrets/hosts/myhost/myapp.cred;   # store path: fine, it's sealed
```

Blobs are per-host. Without a TPM, `--with-key=host` binds to
`/var/lib/systemd/credential.secret`. Alternatively, drop the sealed blob
into `/etc/credstore.encrypted/dotenvx-myapp` and set both `key.*` options
to null with `LoadCredentialEncrypted=dotenvx-myapp` added manually —
systemd searches the credstore directories when no path is given.

**C. Deployment-tool key push (colmena).**

```nix
deployment.keys."myapp.env.keys" = {
  keyFile = ./deployer-only/myapp.env.keys;
  destDir = "/var/lib/dotenvx";   # /run/keys default doesn't survive reboot
  user = "root"; group = "root"; permissions = "0400";
};
services.dotenvx.services.myapp.key.file = "/var/lib/dotenvx/myapp.env.keys";
```

## Rotation

No `rotate` subcommand exists; the flow is manual, but `DOTENV_PRIVATE_KEY*`
accepting **comma-separated keys** gives a zero-downtime window:

1. Locally: `dotenvx decrypt -f secrets/.env.production`, delete the
   `DOTENV_PUBLIC_KEY_PRODUCTION` line and the old `.env.keys` entry, then
   `dotenvx encrypt -f secrets/.env.production` — fresh keypair and
   ciphertext.
2. On hosts: set `DOTENV_PRIVATE_KEY_PRODUCTION="<new>,<old>"` (re-seal the
   blob in strategy B). Running units are untouched; restarts decrypt
   either generation.
3. `nixos-rebuild switch` the new ciphertext.
4. Drop `<old>` once past your rollback horizon — an old generation plus a
   new-only key means broken restarts.

## Verified behaviors this module designs around

Audited against the published `@dotenvx/dotenvx` 1.75.1 package, not docs:

**`dotenvx run` is spawn, not exec.** It launches your command as an
`execa` child and stays resident — a Node parent as MainPID breaks
`Type=notify`/`sd_notify`/watchdog wiring (relevant to anything using the
BEAM `systemd` library), skews cgroup memory accounting, and keeps
private-key material in a long-lived Node heap. The module therefore uses
transient `get` + shell `exec`; MainPID is your binary.

**`--format eval` is not shell-safe.** Its escaping is `JSON.stringify`,
which leaves `$(…)` and backticks live inside double quotes. Combined with
the fact that the embedded *public* key lets any repo writer add or replace
values, `eval "$(dotenvx get --format eval)"` is remote code execution at
service start for anyone who can commit. Decrypted values are semi-trusted
input at the injection boundary; the wrapper owns that boundary and moves
values only through NUL-delimited `read`/`export`/`printf` — no `eval`
anywhere. Keys are validated as identifiers and rejected loudly otherwise.

**The decrypt path is offline.** `get`/`run` make no network calls; the
`https://dotenvx.sh/VERSION` update check fires only from `armor`/`login`
commands, and the commercial Armor paths honor `DOTENVX_NO_ARMOR=true`,
which the wrapper pins. A throwaway `$HOME` is set because dotenvx keeps
CLI settings under it.

## Threat model

Protected: secrets at rest in git, the store, binary caches, and deploy
transport; plaintext never on persistent disk; the credential ramfs is
unit-private and unswappable; repo access (public key) lets a teammate add
secrets but read none; decryption failures fail the unit closed
(`--strict` defaults on here).

Residual, `env` mode: same-UID `/proc/environ`, child inheritance, env
dumps — mitigated by `DynamicUser`, the default `ProtectProc` hardening,
and ultimately by switching to `files` mode.

Residual, host level: swap and core dumps are the two ways "never on
persistent disk" can leak sideways. The default `hardening` closes dumps
per unit (`LimitCORE=0` + `CoredumpFilter=0`; host-wide alternative:
`systemd.coredump.extraConfig = "Storage=none"`). Swap is yours to close:
`preventSwap` pins a single unit's pages, and host-wide encrypted swap
covers everything else — on NixOS a one-liner,
[`swapDevices.*.randomEncryption`](https://search.nixos.org/options?show=swapDevices.*.randomEncryption.enable)
for dm-crypt with an ephemeral key, or
[`zramSwap.enable`](https://search.nixos.org/options?show=zramSwap.enable)
to keep swap in compressed RAM and off disk entirely (background:
[Arch wiki, dm-crypt swap encryption](https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption)).
macOS encrypts swap by default.

Residual, both modes: root on the host (always game over), and secrets in
the *application's* heap — swappable unless `preventSwap` (or the
host-wide measures above), and readable by
anything with ptrace-equivalent access to the process. On the BEAM,
remember `os:getenv/1` is reachable from any code in the node including a
remote shell: files mode plus read-once-at-boot into guarded state (and
`process_flag(sensitive, true)` on the holder) beats leaving them in the
environment for the node's lifetime.

## postmaster: the dotenvx → systemd credential bridge

`postmaster/` contains postmaster, a ~480-line dependency-lean Rust daemon
(edition 2024; pure-Rust crypto, no openssl; no async runtime; syscalls via
rustix's `linux_raw` backend rather than libc FFI, leaving exactly **one**
`unsafe` block in the program — the fd-ownership assertion at the systemd
socket-activation boundary; ~650 KB binary) that serves decrypted dotenvx
values as systemd `LoadCredential=` AF_UNIX sources. systemd's documented contract for socket credential sources is
minimal — the manager connects once at process invocation and reads until
EOF, with no request metadata in-band — so the request is encoded in the
*path*: one socket per (service, key). The module generates a single
`dotenvx-credd.socket` unit carrying N `ListenStream=` entries; postmaster
maps each inherited fd back to its path via `getsockname(2)`.

```nix
services.dotenvx = {
  enable = true;
  daemon.enable = true;   # daemon key: /var/lib/dotenvx/.env.keys, or
                          # daemon.key.encryptedFile = ./hosts/myhost/keys.cred
                          # (seal with: systemd-creds encrypt --name=keys …)
  services.myapp = {
    mode = "credentials";
    envFiles = [ ./secrets/.env.production ];
    credentialKeys = [ "DATABASE_URL" "API_TOKEN" ];
    execStart = "${lib.getExe pkgs.hello} --listen 127.0.0.1:8080";
  };
};
```

Sequence at `systemctl start myapp`: systemd connects (as root) to
`/run/dotenvx-credd/myapp/DATABASE_URL.sock`; the socket unit activates
postmaster if needed; postmaster verifies the peer is uid 0, parses the
env file fresh from the store, tries each comma-separated private key
(rotation-aware), writes the plaintext bytes, closes; systemd places them
at `$CREDENTIALS_DIRECTORY/DATABASE_URL` inside myapp's namespace before
myapp's first instruction executes.

Fail-closed is structural, not aspirational: postmaster **preflights every
configured credential at startup** — a wrong key, missing entry, or
unparseable file aborts before any socket is served, so consumers see
connection-refused ⇒ `LoadCredential` fails ⇒ unit fails. An empty
credential is never served. The daemon receives its own `.env.keys` via
its *own* `LoadCredential` (credentials all the way down), refuses
plaintext keys from `/nix/store` at both eval and runtime, runs
`DynamicUser` under a full sandbox (`PrivateNetwork`,
`RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, syscall-filtered, `MemorySwapMax=0`), marks
itself non-dumpable, `mlockall`s, and zeroizes key material and values.
It performs **no** `${VAR}` expansion by design — values are opaque bytes,
and expansion is where injection bugs live.

Verified against the real implementation, not the docs: fixtures encrypted
with the published dotenvx 1.75.1 CLI decrypt byte-exact through the Rust
`ecies` crate (secp256k1 + HKDF-SHA256 + AES-256-GCM, the family's 16-byte
nonce default), including values containing `$(…)`, backticks, quotes, and
embedded newlines; the comma-separated multi-key rotation path was
exercised with a bogus first key; plaintext (`--plain`) values pass
through; and preflight aborts on a misconfigured key before any socket
exists.

On Linux, postmaster is socket-activated: the `dotenvx-credd.socket` unit
owns the sockets and the daemon inherits them via `sd_listen_fds`. On macOS
it runs `--bind` (launchd has no socket-credential contract), owning the
same per-(service,key) socket paths itself; the syscall layer is
`cfg`-gated (`SO_PEERCRED`→`getpeereid`, `prctl`/`mlockall`→core-limit +
`PT_DENY_ATTACH`), one `unsafe` on each platform. See below.

## macOS (nix-darwin)

`darwinModules.envelope` (alias `darwinModules.dotenvx`; batteries-included
`darwinModules.default` also applies the overlay providing
`pkgs.postmaster`) exposes the **same `services.dotenvx` option tree** as
NixOS. The wrapper internals — file staging, `dotenvx get` assembly, and the
eval-free NUL-delimited injection — are shared verbatim via `modules/lib.nix`
and are exec-identical to the NixOS wrappers. What changes is the substrate
under each mode, because launchd is not systemd:

| | NixOS (systemd) | macOS (launchd) |
|---|---|---|
| key delivery | `LoadCredential=` ramfs; TPM2/host-sealed `key.encryptedFile` | `key.file` read directly by the wrapper **as the service user** (must be readable by it); no sealed-blob analog — or `key.keychainService` via the macOS Keychain (needs dotenvx-rs) |
| `files` mode | one file per key on a namespace-private tmpfs (`TemporaryFileSystem=`) | one file per key on a `0700` per-service dir on an HFS **RAM disk** mounted by the `dotenvx-ramdisk` job; the wrapper hard-verifies the mount and **fails closed** rather than write plaintext to persistent disk |
| `credentials` mode | postmaster socket-activated; `LoadCredential=` per-(svc,key) socket | postmaster runs `--bind` (owns its sockets); the wrapper `postmaster fetch`es each key onto the RAM disk and exports `$CREDENTIALS_DIRECTORY/<KEY>` — **same path convention as systemd credentials**, so app code is unchanged |
| peer authz | `SO_PEERCRED` uid 0 | `getpeereid` (root or the socket's `peer_user`) plus a `0500` owner-only socket dir |

Honest degradations vs Linux: macOS has no mount namespaces, so the
files-mode RAM disk is protected by ownership (`0700`), not invisibility.
macOS swap is encrypted by default (covering RAM-disk pages that do swap
out), but there is no per-service `MemorySwapMax=0` knob and no
`ProtectProc`/sandbox pile — so the darwin module omits the `preventSwap`
and `hardening` options and `key.encryptedFile`. In `credentials` mode
plaintext transits the consumer wrapper for microseconds (on Linux, pid 1
fetches it before the process exists). **Windows** rides NixOS-WSL, which
runs real systemd, so the *NixOS* module works there unchanged — credentials
mode included.

```nix
# darwin.nix
services.dotenvx = {
  enable = true;
  daemon.enable = true;
  daemon.key.file = "/var/lib/dotenvx/.env.keys";   # 0400 root; no sealed blob on darwin
  services.myapp = {
    mode = "credentials";
    envFiles = [ ./secrets/.env.production ];
    credentialKeys = [ "DATABASE_URL" "API_TOKEN" ];
    execStart = "${lib.getExe pkgs.hello} --listen 127.0.0.1:8080";
  };
};
# credentials-mode consumers connect as their own user; declare it and the
# module wires peer_user + the 0500 socket dir to match:
launchd.daemons.myapp.serviceConfig.UserName = "_myapp";
```

Verified natively on aarch64-darwin, not asserted: `nix flake check` builds
the darwin postmaster; `env` mode decrypts real dotenvx ciphertext with
shell metacharacters (`;`, `|`, quotes, glob, embedded newline) arriving
byte-exact and inert; `files` mode writes `0600` secret files plus
`<KEY>_FILE` pointers to a real RAM disk and fails closed when it is absent;
and postmaster's `fetch` round-trip, `getpeereid` denial, comma-key
rotation, and fail-closed preflight all pass through the same Rust binary
the module ships.

## Operational notes

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
