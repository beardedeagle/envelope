# postmaster: the dotenvx → systemd credential bridge

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
`PT_DENY_ATTACH`), one `unsafe` on each platform. See
[macOS (nix-darwin)](./macos.md).
