# Key provisioning

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
