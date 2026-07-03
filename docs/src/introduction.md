# Introduction

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
self-binding its sockets. See [macOS (nix-darwin)](./macos.md).
