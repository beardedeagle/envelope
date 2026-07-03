# Threat model

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
