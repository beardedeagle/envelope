# modules/lib.nix
#
# Platform-independent core shared by the NixOS and nix-darwin modules, so
# staging and injection semantics cannot drift between platforms: encrypted
# env files staged under store-legal names, `dotenvx get` argument assembly,
# and the eval-free NUL-delimited injection fragments (design invariant 3 in
# modules/envelope.nix).
{ lib, pkgs }:

let
  inherit (lib)
    concatMap concatMapStringsSep concatStringsSep escapeShellArg
    escapeShellArgs getExe optional;
  jq = getExe pkgs.jq;
in
rec {
  isIdent = k: builtins.match "[A-Za-z_][A-Za-z0-9_]*" k != null;

  # Re-import each source file under a store-legal name so dotted repo files
  # (.env.production) behave identically in flake and non-flake evaluation.
  stagedSource = f: builtins.path { path = f.file; name = "dotenvx-src"; };

  mkEnvDir = name: sc:
    pkgs.runCommand "dotenvx-env-${name}"
      { preferLocalBuild = true; allowSubstitutes = false; }
      ''
        mkdir -p "$out"
        ${concatMapStringsSep "\n"
          (f: ''cp ${stagedSource f} "$out"/${escapeShellArg f.name}'')
          sc.envFiles}
      '';

  mkGetArgs = envDir: sc: escapeShellArgs (
    [ "get" ]
    ++ concatMap (f: [ "-f" "${envDir}/${f.name}" ]) sc.envFiles
    ++ optional sc.strict "--strict"
    ++ optional sc.overload "--overload"
    ++ sc.extraGetFlags
    ++ [ "--format" "json" ]
  );

  # Embedded as shell comments in the emitted wrapper (they survive
  # `systemctl cat` / `launchctl` inspection), so the injection contract is
  # legible at the call site on both platforms.
  armorPreamble = ''
    # dotenvx keeps CLI settings under $HOME/$DOTENVX_CONFIG; hardened
    # services often have neither. Pin the commercial "armor" code paths
    # off: the decrypt path is offline (verified) and stays that way.
    export HOME="''${HOME:-''${TMPDIR:-/tmp}}"
    export DOTENVX_NO_ARMOR=true
  '';

  validateJson = name: ''
    ${jq} -e 'type == "object"' <<<"$json" >/dev/null

    # Keys become shell identifiers / filenames; refuse anything exotic
    # loudly rather than dropping it silently.
    bad=$(${jq} -r 'keys[] | select(test("^[A-Za-z_][A-Za-z0-9_]*$") | not)' <<<"$json")
    if [ -n "$bad" ]; then
      echo "envelope(${name}): refusing non-identifier key(s): $bad" >&2
      exit 1
    fi
  '';

  injectEnv = ''
    # NUL-delimited, eval-free injection. `export "$kv"` treats the value
    # as data; shell metacharacters (; | quotes glob newlines) arrive inert.
    # Note: dotenvx `get` itself interpolates $(...)/''${VAR}/$VAR in values
    # before we see them (its documented feature) — use credentials mode for
    # values from untrusted contributors.
    while IFS= read -r -d "" kv; do
      export "$kv"
    done < <(${jq} -j 'to_entries[]
      | select(.key | startswith("DOTENV_") | not)
      | "\(.key)=\(.value)\u0000"' <<<"$json")

    unset json
    exec "$@"
  '';

  injectFiles = { secretsDir, passthrough }: ''
    # files mode: one file per key under a private secrets dir (a
    # namespace-private tmpfs on Linux, an HFS ramdisk on darwin). Only
    # <KEY>_FILE pointers (non-secret) enter the environment, plus explicit
    # envPassthrough exceptions.
    umask 077
    while IFS= read -r -d "" k && IFS= read -r -d "" v; do
      printf "%s" "$v" > ${secretsDir}/"$k"
      export "''${k}_FILE=${secretsDir}/$k"
      case " ${concatStringsSep " " passthrough} " in
        *" $k "*) export "$k=$v" ;;
      esac
    done < <(${jq} -j 'to_entries[]
      | select(.key | startswith("DOTENV_") | not)
      | "\(.key)\u0000\(.value)\u0000"' <<<"$json")
    export DOTENVX_SECRETS_DIR=${secretsDir}

    unset json
    exec "$@"
  '';
}
