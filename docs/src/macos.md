# macOS (nix-darwin)

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
