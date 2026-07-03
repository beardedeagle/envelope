# modules/envelope.nix
#
# envelope — dotenvx secrets for NixOS. (nix-side packaging + module)
#
# The Rust "postmaster" daemon lives under ../postmaster/.
#
# Design invariants:
#
#   1. Encrypted `.env.*` files are PUBLIC artifacts. dotenvx encrypts each
#      value with ECIES/secp256k1, so ciphertext is safe in the
#      world-readable Nix store and rides the system closure. Deploys are
#      atomic and declarative; secrets roll back with the generation.
#
#   2. The ONLY secret is the dotenvx private key. It never enters the store
#      as plaintext; it reaches units via systemd credentials
#      (LoadCredential= from an out-of-band keys file, or
#      LoadCredentialEncrypted= from a host/TPM2-sealed blob that IS
#      store-safe). systemd exposes credentials on a unit-private,
#      unswappable ramfs.
#
#   3. Decryption is TRANSIENT and the shell-quoting boundary is OURS:
#      decrypted values are semi-trusted input (the embedded public key
#      grants write to any repo contributor) and move only through
#      NUL-delimited read/export/printf — never eval. dotenvx's own
#      eval/shell output formats are not safely escaped and are not used.
#
#   4. Three injection modes per service:
#        mode = "env"          values exported into the process environment
#                              (12-factor default; /proc environ + child
#                              inheritance exposure are inherent to env).
#        mode = "files"        one file per key on a namespace-private tmpfs
#                              (TemporaryFileSystem=); only <KEY>_FILE
#                              pointers enter the environment.
#        mode = "credentials"  real systemd credentials, served on demand by
#                              the postmaster daemon over per-(service,key)
#                              AF_UNIX sockets (LoadCredential= sources).
#                              Consumers read $CREDENTIALS_DIRECTORY/<KEY>
#                              from unswappable, unit-private ramfs; no
#                              dotenvx/Node in the consumer's start path at
#                              all.
#
#   postmaster (see postmaster/ in this repo) exists because systemd's AF_UNIX
#   credential contract carries no request metadata in-band — the manager
#   connects once at process invocation and reads until EOF — so the request
#   is encoded in the socket *path*. One dotenvx-credd.socket unit carries N
#   ListenStream= entries; the daemon maps inherited fds back to paths via
#   getsockname(2). It preflights every configured credential at startup and
#   refuses to serve otherwise: no daemon ⇒ connection refused ⇒
#   LoadCredential fails ⇒ consumer unit fails. Fail-closed, never an empty
#   credential.

{ config, lib, pkgs, ... }:

let
  inherit (lib)
    mkOption mkEnableOption mkPackageOption mkIf mkMerge mkForce mkDefault
    types literalExpression escapeShellArg escapeShellArgs
    mapAttrs mapAttrsToList concatMapStringsSep concatMap concatStringsSep
    concatLists filterAttrs nameValuePair listToAttrs head
    optional flatten length unique hasPrefix getExe all;

  cfg = config.services.dotenvx;

  envlib = import ./lib.nix { inherit lib pkgs; };

  credId = name: "dotenvx-${name}";

  secretsDir = "/run/dotenvx";        # files mode, namespace-private tmpfs
  credDir = "/run/dotenvx-credd";     # credentials mode, postmaster sockets

  credServices = filterAttrs (_: sc: sc.mode == "credentials") cfg.services;
  daemonActive = cfg.daemon.enable && credServices != { };

  sockPath = svc: key: "${credDir}/${svc}/${key}.sock";

  # credentials mode: consumers read $CREDENTIALS_DIRECTORY/<KEY> directly;
  # this wrapper only exports non-secret path pointers for _FILE-convention
  # apps. No dotenvx, no jq, no secret ever touches the shell.
  mkCredWrapper = name: sc:
    pkgs.writeShellScript "dotenvx-credentials-${name}" ''
      set -euo pipefail
      : "''${CREDENTIALS_DIRECTORY:?postmaster credentials expected but CREDENTIALS_DIRECTORY is unset}"
      ${concatMapStringsSep "\n"
        (k: ''export ${k}_FILE="''${CREDENTIALS_DIRECTORY}/${k}"'')
        sc.credentialKeys}
      export DOTENVX_SECRETS_DIR="''${CREDENTIALS_DIRECTORY}"
      exec "$@"
    '';

  mkDecryptWrapper = name: sc:
    let
      envDir = envlib.mkEnvDir name sc;
      getArgs = envlib.mkGetArgs envDir sc;
    in
    pkgs.writeShellScript "dotenvx-${sc.mode}-${name}" (''
      set -euo pipefail

    ''
    + envlib.armorPreamble
    + ''

      keysArgs=()
      if [ -n "''${CREDENTIALS_DIRECTORY:-}" ] \
         && [ -r "''${CREDENTIALS_DIRECTORY}/${credId name}" ]; then
        keysArgs=(--env-keys-file "''${CREDENTIALS_DIRECTORY}/${credId name}")
      fi
      # No credential present => dotenvx falls back to DOTENV_PRIVATE_KEY*
      # in the environment (external provisioning; key.file = null).

      # Decrypt exactly once, transiently. Node exits before the service
      # starts; command substitution is caught by `set -e`, so a decryption
      # failure under --strict fails the unit instead of starting it bare.
      json=$(${getExe cfg.package} ${getArgs} "''${keysArgs[@]}")

    ''
    + envlib.validateJson name
    + (if sc.mode == "env" then envlib.injectEnv
       else envlib.injectFiles {
         inherit secretsDir;
         passthrough = sc.envPassthrough;
       }));

  mkWrapper = name: sc:
    if sc.mode == "credentials"
    then mkCredWrapper name sc
    else mkDecryptWrapper name sc;

  # postmaster's config: world-readable JSON, contains no secrets — only
  # store paths (public ciphertext) and key *names*.
  daemonConfig = pkgs.writeText "postmaster-config.json" (builtins.toJSON {
    keys.credential = "keys";
    credentials = listToAttrs (concatLists (mapAttrsToList
      (svc: sc:
        map
          (key: nameValuePair (sockPath svc key) {
            env_file = "${envlib.mkEnvDir svc sc}/${(head sc.envFiles).name}";
            inherit key;
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
          `env`: decrypted values exported into the service's environment
          (visible in /proc/<pid>/environ to root and the same UID;
          inherited by children).
          `files`: values written one-file-per-key to a namespace-private
          tmpfs; only `<KEY>_FILE` path pointers are exported.
          `credentials`: real systemd credentials served by the postmaster
          daemon; the app reads $CREDENTIALS_DIRECTORY/<KEY> from
          unit-private unswappable ramfs. Requires
          services.dotenvx.daemon.enable and an explicit `credentialKeys`
          list. Strongest hygiene; no dotenvx/Node in the consumer's start
          path.
        '';
      };

      credentialKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "DATABASE_URL" "API_TOKEN" ];
        description = ''
          `credentials` mode only: which keys from the env file to expose,
          one AF_UNIX socket and one systemd credential each. Explicit by
          design — consumers need to know these names anyway.
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

      key = {
        file = mkOption {
          type = types.nullOr types.str;
          default = "/var/lib/dotenvx/.env.keys";
          description = ''
            Absolute path — on the target host, OUTSIDE the Nix store — to a
            plaintext `.env.keys` file, delivered via LoadCredential=.
            Missing file ⇒ unit fails to start (fail-closed). Ignored in
            `credentials` mode, where keys live on the daemon instead.
          '';
        };
        encryptedFile = mkOption {
          type = types.nullOr (types.either types.path types.str);
          default = null;
          description = ''
            `systemd-creds encrypt` blob of the keys file, delivered via
            LoadCredentialEncrypted= (takes precedence over key.file). Must
            be encrypted with `--name=dotenvx-<serviceName>`. Sealed to
            host key and/or TPM2, so a Nix store path is acceptable here.
            Ignored in `credentials` mode.
          '';
        };
      };

      strict = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Pass `--strict` to the decrypt step (`env`/`files` modes): any
          decryption error fails the unit instead of starting it with
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
          Command line to wrap; the module mkForce's the unit's ExecStart to
          `<wrapper> <execStart>`. In `credentials` mode the wrapper only
          exports non-secret `<KEY>_FILE` pointers into
          $CREDENTIALS_DIRECTORY. When null, only the plumbing is generated
          — compose ExecStart yourself via
          `config.services.dotenvx.wrappers.<name>`, or (credentials mode)
          skip the wrapper entirely and read $CREDENTIALS_DIRECTORY/<KEY>.
        '';
      };

      preventSwap = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Set MemorySwapMax=0 on the unit: the cgroup's pages — including
          the files-mode tmpfs and the app heap holding secrets — can never
          reach swap. Tradeoff: under memory pressure the unit OOMs instead
          of swapping.
        '';
      };

      hardening = mkOption {
        type = types.bool;
        default = true;
        description = ''
          mkDefault ProtectProc=invisible, ProcSubset=pid,
          NoNewPrivileges=true, LimitCORE=0, CoredumpFilter=0 (a core
          dump of a secret-holding process is plaintext on disk). Cheap
          surface reduction; all overridable per-unit.
        '';
      };
    };
  };
in
{
  options.services.dotenvx = {
    enable = mkEnableOption "dotenvx-encrypted secrets for systemd services";

    package = mkPackageOption pkgs "dotenvx" { };

    installCLI = mkOption {
      type = types.bool;
      default = false;
      description = "Add the dotenvx CLI to environment.systemPackages for host-side ops.";
    };

    daemon = {
      enable = mkEnableOption ''
        postmaster, the dotenvx → systemd credential bridge required by
        services using mode = "credentials"
      '';

      package = mkPackageOption pkgs "postmaster" { };

      key = {
        file = mkOption {
          type = types.nullOr types.str;
          default = "/var/lib/dotenvx/.env.keys";
          description = ''
            Absolute path (outside the Nix store) to the `.env.keys` file
            postmaster decrypts with, delivered via the daemon's own
            LoadCredential=. Credentials all the way down.
          '';
        };
        encryptedFile = mkOption {
          type = types.nullOr (types.either types.path types.str);
          default = null;
          description = ''
            `systemd-creds encrypt` blob of the keys file for the daemon
            (LoadCredentialEncrypted=; takes precedence over key.file).
            Must be encrypted with `--name=keys`. Store paths are fine —
            the blob is host/TPM2-sealed.
          '';
        };
      };
    };

    services = mkOption {
      type = types.attrsOf serviceType;
      default = { };
      description = "Per-systemd-service dotenvx wiring; attribute name = unit name (without .service).";
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
          store; seal first and use key.encryptedFile instead.
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
        assertion = !cfg.daemon.enable
          || cfg.daemon.key.encryptedFile != null
          || (cfg.daemon.key.file != null
            && !(hasPrefix builtins.storeDir cfg.daemon.key.file));
        message = ''
          services.dotenvx.daemon: provide key.file (outside the Nix store)
          or key.encryptedFile; postmaster refuses plaintext keys from the
          store at runtime, and this module refuses them at eval.
        '';
      }
    ]);

    warnings = flatten (mapAttrsToList (name: sc:
      optional (sc.key.file != null && sc.key.encryptedFile != null && sc.mode != "credentials")
        "services.dotenvx.services.${name}: both key.file and key.encryptedFile set; encryptedFile wins."
      ++ optional (sc.mode != "files" && sc.envPassthrough != [ ])
        "services.dotenvx.services.${name}: envPassthrough is only meaningful in files mode."
      ++ optional (sc.mode != "credentials" && sc.credentialKeys != [ ])
        "services.dotenvx.services.${name}: credentialKeys is only meaningful in credentials mode."
      ++ optional (!all (f: hasPrefix ".env" f.name) sc.envFiles)
        "services.dotenvx.services.${name}: a staged env file does not follow the `.env*` naming convention; dotenvx private-key selection may not resolve."
    ) cfg.services
    ++ optional (cfg.daemon.enable && credServices == { })
      "services.dotenvx.daemon is enabled but no service uses mode = \"credentials\"; the daemon units are not generated.");

    environment.systemPackages = mkIf cfg.installCLI [ cfg.package ];

    systemd.sockets = mkIf daemonActive {
      dotenvx-credd = {
        description = "postmaster credential sockets (dotenvx → systemd bridge)";
        wantedBy = [ "sockets.target" ];
        listenStreams = concatLists (mapAttrsToList
          (svc: sc: map (key: sockPath svc key) sc.credentialKeys)
          credServices);
        socketConfig = {
          # Only the service manager (root) may connect; postmaster also
          # verifies SO_PEERCRED uid 0 in depth.
          SocketMode = "0600";
          SocketUser = "root";
          SocketGroup = "root";
          DirectoryMode = "0755";
          RemoveOnStop = true;
          Backlog = 64;
        };
      };
    };

    systemd.services = mkMerge [
      (mapAttrs
        (name: sc: mkMerge [
          {
            serviceConfig = mkMerge [
              (mkIf (sc.mode != "credentials" && sc.key.encryptedFile != null) {
                LoadCredentialEncrypted = [ "${credId name}:${toString sc.key.encryptedFile}" ];
              })
              (mkIf (sc.mode != "credentials" && sc.key.encryptedFile == null && sc.key.file != null) {
                LoadCredential = [ "${credId name}:${sc.key.file}" ];
              })
              (mkIf (sc.mode == "files") {
                # Namespace-private tmpfs: invisible outside the unit's
                # mount ns, destroyed with it. 1777+umask 077 lets the
                # (possibly Dynamic) service user write without root
                # choreography.
                TemporaryFileSystem = [ "${secretsDir}:mode=1777,nosuid,nodev,noexec" ];
              })
              (mkIf (sc.execStart != null) {
                ExecStart = mkForce "${cfg.wrappers.${name}} ${sc.execStart}";
              })
              (mkIf sc.preventSwap {
                MemorySwapMax = mkDefault 0;
              })
              (mkIf sc.hardening {
                ProtectProc = mkDefault "invisible";
                ProcSubset = mkDefault "pid";
                NoNewPrivileges = mkDefault true;
                # No plaintext core dumps: LimitCORE=0 makes the kernel skip
                # the dump (piped handlers like systemd-coredump included);
                # CoredumpFilter=0 empties it in depth if something inside
                # the unit re-raises the limit.
                LimitCORE = mkDefault 0;
                CoredumpFilter = mkDefault "0";
              })
            ];
          }
          (mkIf (sc.mode == "credentials") {
            wants = [ "dotenvx-credd.socket" ];
            after = [ "dotenvx-credd.socket" ];
            serviceConfig.LoadCredential =
              map (k: "${k}:${sockPath name k}") sc.credentialKeys;
          })
        ])
        cfg.services)

      (mkIf daemonActive {
        dotenvx-credd = {
          description = "postmaster — dotenvx → systemd credential bridge";
          serviceConfig = {
            ExecStart = "${getExe cfg.daemon.package} --config ${daemonConfig}";
            Restart = "on-failure";
            RestartSec = 2;

            # Keys for the daemon itself arrive as its own credential.
            LoadCredential = mkIf (cfg.daemon.key.encryptedFile == null && cfg.daemon.key.file != null)
              [ "keys:${cfg.daemon.key.file}" ];
            LoadCredentialEncrypted = mkIf (cfg.daemon.key.encryptedFile != null)
              [ "keys:${toString cfg.daemon.key.encryptedFile}" ];

            # This process holds every private key: sandbox accordingly.
            DynamicUser = true;
            CapabilityBoundingSet = [ "" ];
            NoNewPrivileges = true;
            PrivateNetwork = true;
            RestrictAddressFamilies = [ "AF_UNIX" ];
            IPAddressDeny = "any";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            PrivateDevices = true;
            DevicePolicy = "closed";
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectKernelLogs = true;
            ProtectClock = true;
            ProtectControlGroups = true;
            ProtectHostname = true;
            ProtectProc = "invisible";
            ProcSubset = "pid";
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            KeyringMode = "private";
            SystemCallFilter = [ "@system-service" "~@privileged" ];
            SystemCallArchitectures = "native";
            SystemCallErrorNumber = "EPERM";
            UMask = "0077";
            MemorySwapMax = 0;
            # postmaster marks itself non-dumpable; this is the unit-level belt.
            LimitCORE = 0;
            # Headroom for mlockall() of the daemon's address space.
            LimitMEMLOCK = "64M";
          };
        };
      })
    ];
  };
}
