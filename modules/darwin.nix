# modules/darwin.nix
#
# envelope — dotenvx secrets for nix-darwin (launchd).
#
# Same services.dotenvx.* option surface as the NixOS module, same public
# ciphertext-in-store design, same eval-free injection (shared via ./lib.nix
# so the two platforms cannot drift). What differs is the substrate:
#
#   * Key delivery: launchd has no LoadCredential. The private-keys file is
#     read directly from key.file by the wrapper, AS THE SERVICE USER — it
#     must be readable by that user (per-service key files or group perms),
#     and the wrapper fails closed if it is missing or unreadable. There is
#     no systemd-creds/TPM2 sealed-blob analog, so no key.encryptedFile.
#     Alternatively key.keychainService reads DOTENV_PRIVATE_KEY* from the
#     macOS Keychain (System keychain for daemons) via a dotenvx CLI that
#     implements --env-keys-keychain (dotenvx-rs) — the closest darwin
#     analog to sealed key delivery: nothing key-shaped in the filesystem
#     outside the keychain's own encrypted storage.
#
#   * files mode: launchd has no TemporaryFileSystem=. A root launchd job
#     (dotenvx-ramdisk) mounts a small HFS+ ramdisk at ramdisk.mountPoint
#     (nobrowse,owners,nosuid,nodev,noexec) and pre-creates one 0700
#     per-service directory owned by each consumer's UserName. Wrappers
#     hard-verify the mount before writing a byte — "plaintext never touches
#     persistent disk" survives; what is lost vs Linux is mount-namespace
#     privacy (macOS has no mount namespaces; the fs ACL is ownership, not
#     invisibility). macOS swap is encrypted by default, which also covers
#     ramdisk pages that swap out; there is no per-service swap knob, so no
#     preventSwap option. There are no ProtectProc/ProcSubset analogs
#     either, so no hardening option.
#
#   * credentials mode: postmaster runs as a root launchd daemon in --bind
#     mode (macOS has no socket-activation credential contract to bridge
#     to); consumer wrappers pull each key through `postmaster fetch` onto
#     the ramdisk and export CREDENTIALS_DIRECTORY, so application code
#     reads $CREDENTIALS_DIRECTORY/<KEY> identically on both platforms.
#     Authorization is per-socket and enforced twice: the socket's parent
#     directory is owned by the consumer's UserName (mode 0500), and
#     postmaster checks getpeereid against the same user (peer_user).
#     Unlike Linux — where pid 1 fetches credentials before the process
#     exists — the wrapper does the fetching here, so plaintext transits
#     the wrapper for microseconds.

{ config, lib, pkgs, ... }:

let
  inherit (lib)
    mkOption mkEnableOption mkPackageOption mkIf mkMerge mkForce mkDefault
    types literalExpression escapeShellArg optionalString
    mapAttrs mapAttrsToList concatMapStringsSep concatStringsSep
    concatLists filterAttrs nameValuePair listToAttrs head
    optional flatten length unique hasPrefix getExe all;

  cfg = config.services.dotenvx;

  envlib = import ./lib.nix { inherit lib pkgs; };

  credDir = "/private/var/run/dotenvx-credd";
  sockPath = svc: key: "${credDir}/${svc}/${key}.sock";

  credServices = filterAttrs (_: sc: sc.mode == "credentials") cfg.services;
  daemonActive = cfg.daemon.enable && credServices != { };

  # files AND credentials modes stage plaintext on the ramdisk.
  ramdiskServices = filterAttrs (_: sc: sc.mode != "env") cfg.services;
  ramdiskActive = ramdiskServices != { };

  # The launchd UserName of a consumer daemon (absent/null ⇒ root). Read
  # from the merged launchd config so the user's own UserName declaration is
  # the single source of truth for socket-dir ownership, ramdisk-dir
  # ownership, and postmaster's peer_user check alike.
  svcUser = name:
    let
      u =
        if config.launchd.daemons ? ${name}
        then config.launchd.daemons.${name}.serviceConfig.UserName
        else null;
    in
    if u == null then "root" else u;

  # Plaintext lands only on the ramdisk. If it is not mounted (early boot,
  # broken dotenvx-ramdisk job), refuse to write a byte to persistent disk;
  # KeepAlive retries the service until the substrate is up.
  ramdiskGuard = name: ''
    case "$(/sbin/mount)" in
      *" on ${cfg.ramdisk.mountPoint} (hfs"*) ;;
      *)
        echo "envelope(${name}): ${cfg.ramdisk.mountPoint} is not the dotenvx ramdisk; refusing to write plaintext to persistent disk" >&2
        exit 1
        ;;
    esac
    D=${cfg.ramdisk.mountPoint}/${name}
    if [ ! -d "$D" ] || [ ! -O "$D" ]; then
      echo "envelope(${name}): $D missing or not owned by this service user (is dotenvx-ramdisk healthy?)" >&2
      exit 1
    fi
  '';

  # credentials mode: fetch each key from postmaster onto the ramdisk and
  # export CREDENTIALS_DIRECTORY — application code reads
  # $CREDENTIALS_DIRECTORY/<KEY> exactly as it would under systemd. No
  # dotenvx, no jq, no Node in the consumer's start path.
  mkCredWrapper = name: sc:
    pkgs.writeShellScript "dotenvx-credentials-${name}" (''
      set -euo pipefail

    ''
    + ramdiskGuard name
    + ''

      umask 077
    ''
    + concatMapStringsSep "\n" (k: ''
      ${getExe cfg.daemon.package} fetch ${sockPath name k} > "$D/${k}"
      export ${k}_FILE="$D/${k}"
    '') sc.credentialKeys
    + ''

      export CREDENTIALS_DIRECTORY="$D"
      export DOTENVX_SECRETS_DIR="$D"
      exec "$@"
    '');

  mkDecryptWrapper = name: sc:
    let
      envDir = envlib.mkEnvDir name sc;
      getArgs = envlib.mkGetArgs envDir sc;
      secretsDir = "${cfg.ramdisk.mountPoint}/${name}";
    in
    pkgs.writeShellScript "dotenvx-${sc.mode}-${name}" (''
      set -euo pipefail

    ''
    + envlib.armorPreamble
    + ''

      keysArgs=()
    ''
    + (if sc.key.keychainService != null then ''
      # Private keys come from the OS keychain (System keychain for launchd
      # daemons); requires a dotenvx CLI with --env-keys-keychain
      # (dotenvx-rs). A missing keychain item fails the decrypt step under
      # --strict, so this stays fail-closed without a preflight here.
      keysArgs=(--env-keys-keychain ${escapeShellArg sc.key.keychainService})
    '' else if sc.key.file != null then ''
      # launchd has no LoadCredential: read the keys file directly, as the
      # service user, and fail closed if it is not there.
      if [ ! -r ${escapeShellArg sc.key.file} ]; then
        echo "envelope(${name}): keys file ${sc.key.file} missing or unreadable; failing closed" >&2
        exit 1
      fi
      keysArgs=(--env-keys-file ${escapeShellArg sc.key.file})
    '' else ''
      # key.file = null: dotenvx falls back to DOTENV_PRIVATE_KEY* in the
      # environment (external provisioning).
    '')
    + optionalString (sc.mode == "files") ("\n" + ramdiskGuard name)
    + ''

      # Decrypt exactly once, transiently. Node exits before the service
      # starts; a decryption failure under --strict fails the job instead
      # of starting it bare, and KeepAlive retries it.
      json=$(${getExe cfg.package} ${getArgs} "''${keysArgs[@]}")

    ''
    + envlib.validateJson name
    + (if sc.mode == "env" then envlib.injectEnv
       else envlib.injectFiles {
         secretsDir = secretsDir;
         passthrough = sc.envPassthrough;
       }));

  mkWrapper = name: sc:
    if sc.mode == "credentials"
    then mkCredWrapper name sc
    else mkDecryptWrapper name sc;

  # postmaster's config: world-readable JSON, contains no secrets — store
  # paths (public ciphertext), key *names*, and peer user names.
  daemonConfig = pkgs.writeText "postmaster-config.json" (builtins.toJSON {
    keys.file = cfg.daemon.key.file;
    credentials = listToAttrs (concatLists (mapAttrsToList
      (svc: sc:
        map
          (key: nameValuePair (sockPath svc key) {
            env_file = "${envlib.mkEnvDir svc sc}/${(head sc.envFiles).name}";
            inherit key;
            peer_user = svcUser svc;
          })
          sc.credentialKeys)
      credServices));
  });

  envFileType = types.submodule ({ config, ... }: {
    options = {
      file = mkOption {
        type = types.path;
        description = ''
          dotenvx-encrypted env file. Safe to commit and safe in the
          world-readable Nix store — every value is ciphertext and the
          embedded DOTENV_PUBLIC_KEY only permits *adding* secrets.
        '';
      };
      name = mkOption {
        type = types.str;
        default = builtins.baseNameOf config.file;
        defaultText = literalExpression "baseNameOf file";
        description = ''
          Basename the file is staged under. Keep dotenvx's
          `.env.<environment>` convention — it selects which
          DOTENV_PRIVATE_KEY_<ENV> entry decrypts the file.
        '';
      };
    };
  });

  serviceType = types.submodule {
    options = {
      envFiles = mkOption {
        type = types.listOf
          (types.coercedTo types.path (p: { file = p; }) envFileType);
        description = ''
          Ordered list of encrypted env files (repeated `-f`). Without
          `overload`, already-set values win: process environment first,
          then earlier files over later ones. Keys literally starting with
          `DOTENV_` are filtered at injection (dotenvx metadata).
          `credentials` mode requires exactly one file.
        '';
        example = literalExpression ''[ ./secrets/.env ./secrets/.env.production ]'';
      };

      mode = mkOption {
        type = types.enum [ "env" "files" "credentials" ];
        default = "env";
        description = ''
          `env`: decrypted values exported into the daemon's environment.
          `files`: values written one-file-per-key to a per-service 0700
          directory on the dotenvx ramdisk; only `<KEY>_FILE` path pointers
          are exported.
          `credentials`: values fetched from the postmaster daemon onto the
          ramdisk; the app reads $CREDENTIALS_DIRECTORY/<KEY>, same
          convention as systemd credentials on Linux. Requires
          services.dotenvx.daemon.enable and an explicit `credentialKeys`
          list. No dotenvx/Node in the consumer's start path.
        '';
      };

      credentialKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "DATABASE_URL" "API_TOKEN" ];
        description = ''
          `credentials` mode only: which keys from the env file to expose,
          one AF_UNIX socket and one fetched credential file each. Explicit
          by design — consumers need to know these names anyway.
        '';
      };

      envPassthrough = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "DATABASE_URL" ];
        description = ''
          `files` mode only: keys listed here are ALSO exported as real
          environment variables — an escape hatch for the stragglers in an
          otherwise file-capable app.
        '';
      };

      key.file = mkOption {
        type = types.nullOr types.str;
        default = "/var/lib/dotenvx/.env.keys";
        description = ''
          Absolute path — on the target host, OUTSIDE the Nix store — to a
          plaintext `.env.keys` file. Read directly by the wrapper AS THE
          SERVICE USER (launchd has no LoadCredential), so it must be
          readable by that user; missing/unreadable ⇒ the job fails closed.
          Ignored in `credentials` mode, where keys live on the daemon.
        '';
      };

      key.keychainService = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "dotenvx";
        description = ''
          Read private keys from the macOS Keychain instead of a file:
          the wrapper passes `--env-keys-keychain <this>` and dotenvx
          looks up the generic-password item whose account is
          `DOTENV_PRIVATE_KEY[_<ENV>]` under this service name. Takes
          precedence over key.file; ignored in `credentials` mode.
          Requires a dotenvx CLI implementing `--env-keys-keychain`
          (dotenvx-rs; upstream Node dotenvx does not). Provision into
          the System keychain so launchd daemons can read it:

              sudo security add-generic-password -U -A \
                -s <service> -a DOTENV_PRIVATE_KEY_<ENV> -w <64-hex> \
                /Library/Keychains/System.keychain

          (`-A` trusts all applications; tighten to specific binaries
          with repeated `-T` instead once the store path is known.)
        '';
      };

      strict = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Pass `--strict` to the decrypt step (`env`/`files` modes): any
          decryption error fails the job instead of starting it with
          partial secrets. `credentials` mode is unconditionally strict via
          postmaster's preflight.
        '';
      };

      overload = mkOption {
        type = types.bool;
        default = false;
        description = "Pass `--overload`: file values override pre-existing environment variables (`env`/`files` modes).";
      };

      extraGetFlags = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "--convention" "nextjs" ];
        description = "Additional flags for `dotenvx get` (`env`/`files` modes).";
      };

      execStart = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = literalExpression ''"''${pkgs.hello}/bin/hello --listen 127.0.0.1:8080"'';
        description = ''
          Command line to wrap; the module mkForce's the daemon's
          ProgramArguments to `/bin/sh -c "/bin/wait4path /nix/store &&
          exec <wrapper> <execStart>"` (the same wait4path wrapping
          nix-darwin applies to `command`). When null, only the plumbing is
          generated — compose the launchd job yourself via
          `config.services.dotenvx.wrappers.<name>`.
        '';
      };
    };
  };
in
{
  options.services.dotenvx = {
    enable = mkEnableOption "dotenvx-encrypted secrets for launchd daemons";

    package = mkPackageOption pkgs "dotenvx" { };

    installCLI = mkOption {
      type = types.bool;
      default = false;
      description = "Add the dotenvx CLI to environment.systemPackages for host-side ops.";
    };

    ramdisk = {
      mountPoint = mkOption {
        type = types.str;
        default = "/private/var/run/dotenvx";
        description = ''
          Where the dotenvx HFS+ ramdisk is mounted (files/credentials
          modes). Per-service 0700 subdirectories are created beneath it.
        '';
      };
      sizeMB = mkOption {
        type = types.ints.positive;
        default = 16;
        description = ''
          Ramdisk size in MiB. Secrets are tiny; 16 MiB is generous. The
          backing memory is allocated lazily by the kernel.
        '';
      };
    };

    daemon = {
      enable = mkEnableOption ''
        postmaster, the dotenvx credential daemon required by services
        using mode = "credentials" (runs in --bind mode under launchd)
      '';

      package = mkPackageOption pkgs "postmaster" { };

      key.file = mkOption {
        type = types.nullOr types.str;
        default = "/var/lib/dotenvx/.env.keys";
        description = ''
          Absolute path (outside the Nix store) to the `.env.keys` file
          postmaster decrypts with. Read by the daemon as root at startup;
          0400 root:wheel is the right shape. There is no systemd-creds
          sealed-blob analog on darwin.
        '';
      };
    };

    services = mkOption {
      type = types.attrsOf serviceType;
      default = { };
      description = "Per-launchd-daemon dotenvx wiring; attribute name = launchd.daemons.<name>.";
    };

    wrappers = mkOption {
      type = types.attrsOf types.package;
      readOnly = true;
      default = mapAttrs mkWrapper cfg.services;
      defaultText = literalExpression "generated wrapper scripts, one per configured service";
      description = ''
        Generated wrappers, for manual composition:
        `lib.mkForce "''${config.services.dotenvx.wrappers.foo} /path/to/bin args"`.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = flatten (mapAttrsToList (name: sc: [
      {
        assertion = sc.envFiles != [ ];
        message = "services.dotenvx.services.${name}.envFiles must contain at least one encrypted env file.";
      }
      {
        assertion = length (unique (map (f: f.name) sc.envFiles)) == length sc.envFiles;
        message = "services.dotenvx.services.${name}.envFiles: staged basenames collide; set `name` explicitly.";
      }
      {
        assertion = sc.key.file == null || !(hasPrefix builtins.storeDir sc.key.file);
        message = ''
          services.dotenvx.services.${name}.key.file points into the Nix
          store. Plaintext private keys must never enter the world-readable
          store.
        '';
      }
      {
        assertion = all envlib.isIdent sc.envPassthrough && all envlib.isIdent sc.credentialKeys;
        message = "services.dotenvx.services.${name}: envPassthrough/credentialKeys entries must be valid identifiers.";
      }
      {
        assertion = sc.mode != "credentials" || sc.credentialKeys != [ ];
        message = "services.dotenvx.services.${name}: mode = \"credentials\" requires a non-empty credentialKeys list.";
      }
      {
        assertion = sc.mode != "credentials" || length sc.envFiles == 1;
        message = "services.dotenvx.services.${name}: mode = \"credentials\" maps keys from exactly one env file.";
      }
      {
        assertion = sc.mode != "credentials" || cfg.daemon.enable;
        message = "services.dotenvx.services.${name}: mode = \"credentials\" requires services.dotenvx.daemon.enable = true.";
      }
    ]) cfg.services ++ [
      {
        assertion = !daemonActive
          || (cfg.daemon.key.file != null
            && !(hasPrefix builtins.storeDir cfg.daemon.key.file));
        message = ''
          services.dotenvx.daemon: key.file must be set to a path outside
          the Nix store (darwin has no sealed-blob substrate); postmaster
          also refuses store-path keys at runtime.
        '';
      }
    ]);

    warnings = flatten (mapAttrsToList (name: sc:
      optional (sc.mode != "files" && sc.envPassthrough != [ ])
        "services.dotenvx.services.${name}: envPassthrough is only meaningful in files mode."
      ++ optional (sc.mode != "credentials" && sc.credentialKeys != [ ])
        "services.dotenvx.services.${name}: credentialKeys is only meaningful in credentials mode."
      ++ optional (!all (f: hasPrefix ".env" f.name) sc.envFiles)
        "services.dotenvx.services.${name}: a staged env file does not follow the `.env*` naming convention; dotenvx private-key selection may not resolve."
    ) cfg.services
    ++ optional (cfg.daemon.enable && credServices == { })
      "services.dotenvx.daemon is enabled but no service uses mode = \"credentials\"; the daemon job is not generated.");

    environment.systemPackages = mkIf cfg.installCLI [ cfg.package ];

    launchd.daemons = mkMerge [
      (mapAttrs
        (name: sc: mkIf (sc.execStart != null) {
          serviceConfig = {
            # Same wait4path wrapping nix-darwin gives `command`, forced so
            # a consumer's own command/script definition cannot double up.
            ProgramArguments = mkForce [
              "/bin/sh"
              "-c"
              "/bin/wait4path /nix/store && exec ${cfg.wrappers.${name}} ${sc.execStart}"
            ];
            RunAtLoad = mkDefault true;
            # Wrappers exit 1 while the substrate is still coming up at boot
            # (ramdisk mount, postmaster sockets); launchd must retry rather
            # than leave the job dead. Overridable per-daemon.
            KeepAlive = mkDefault { SuccessfulExit = false; };
          };
        })
        cfg.services)

      (mkIf ramdiskActive {
        dotenvx-ramdisk = {
          script = ''
            set -euo pipefail
            MP=${cfg.ramdisk.mountPoint}
            case "$(/sbin/mount)" in
              *" on $MP (hfs"*) ;;
              *)
                dev=$(/usr/bin/hdiutil attach -nomount ram://${toString (cfg.ramdisk.sizeMB * 2048)})
                dev=$(echo $dev)
                /sbin/newfs_hfs -v dotenvx "$dev" >/dev/null
                /bin/mkdir -p "$MP"
                /sbin/mount -t hfs -o nobrowse,owners,nosuid,nodev,noexec "$dev" "$MP"
                /bin/chmod 0755 "$MP"
                ;;
            esac
            ${concatStringsSep "\n"
              (mapAttrsToList
                (name: sc: ''/usr/bin/install -d -m 0700 -o ${svcUser name} "$MP/${name}"'')
                ramdiskServices)}
          '';
          serviceConfig = {
            RunAtLoad = true;
            KeepAlive = { SuccessfulExit = false; };
            StandardErrorPath = "/private/var/log/dotenvx-ramdisk.log";
          };
        };
      })

      (mkIf daemonActive {
        dotenvx-credd = {
          command = "${getExe cfg.daemon.package} --config ${daemonConfig} --bind";
          serviceConfig = {
            RunAtLoad = true;
            KeepAlive = true;
            ThrottleInterval = 2;
            StandardErrorPath = "/private/var/log/dotenvx-credd.log";
            # Runs as root: it reads the 0400 keys file and chowns the
            # per-service socket dirs. launchd has no DynamicUser/sandbox
            # pile; postmaster's own hardening (core limit, PT_DENY_ATTACH,
            # zeroize, preflight) plus the getpeereid checks carry the
            # posture.
          };
        };
      })
    ];
  };
}
