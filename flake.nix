{
  description = ''
    envelope — dotenvx secrets for NixOS and nix-darwin. Encrypted .env
    files ride the Nix store; private keys arrive via systemd credentials
    (optionally TPM2-sealed) or, on darwin, an out-of-store keys file;
    decryption happens only inside the service's exec context, or on demand
    via postmaster, a Rust dotenvx credential daemon (systemd
    socket-activated on Linux, self-binding under launchd on macOS).
  '';

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems
        (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        postmaster = pkgs.callPackage ./postmaster/package.nix { };
        default = postmaster;
      });

      overlays.default = final: _prev: {
        postmaster = final.callPackage ./postmaster/package.nix { };
      };

      nixosModules = rec {
        # The module alone; bring your own pkgs.postmaster (overlay below)
        # if you enable services.dotenvx.daemon.
        # "envelope" is the nix-side name for this module+packaging.
        envelope = import ./modules/envelope.nix;

        # Legacy alias for compatibility during transition.
        dotenvx = envelope;

        # Batteries included: module + overlay providing pkgs.postmaster.
        default = { ... }: {
          imports = [ envelope ];
          nixpkgs.overlays = [ self.overlays.default ];
        };
      };

      darwinModules = rec {
        # nix-darwin analog of nixosModules.envelope: same option tree,
        # launchd substrate (HFS+ ramdisk for files mode, postmaster --bind
        # for credentials mode).
        envelope = import ./modules/darwin.nix;

        dotenvx = envelope;

        default = { ... }: {
          imports = [ envelope ];
          nixpkgs.overlays = [ self.overlays.default ];
        };
      };

      checks = forAll (pkgs:
        {
          postmaster = self.packages.${pkgs.stdenv.hostPlatform.system}.postmaster;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          let
            # Renders the envelope module against a minimal, otherwise-inert
            # NixOS configuration and asserts the hardened serviceConfig
            # this module promises. x86_64-linux is fixed for the inner
            # nixosSystem eval (config values only, no cross-build); the
            # outer forAll still gates the check itself to Linux hosts.
            moduleEvalSystem = nixpkgs.lib.nixosSystem {
              system = "x86_64-linux";
              modules = [
                self.nixosModules.envelope
                {
                  services.dotenvx = {
                    enable = true;
                    services.myapp = {
                      envFiles = [ ./tests/fixtures/.env.production ];
                      execStart = "/bin/myapp";
                    };
                  };
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "/dev/sda1";
                    fsType = "ext4";
                  };
                  system.stateVersion = "25.05";
                }
              ];
            };
            sc = moduleEvalSystem.config.systemd.services.myapp.serviceConfig;
            checksOk = sc.LimitCORE == 0
              && sc.CoredumpFilter == "0"
              && sc.ProtectProc == "invisible";
          in
          {
            module-eval = pkgs.runCommand "envelope-module-eval-check" { } ''
              ${if checksOk then "" else builtins.throw ''
                module-eval: hardened serviceConfig did not render as expected
                  LimitCORE=${builtins.toJSON sc.LimitCORE} (want 0)
                  CoredumpFilter=${builtins.toJSON sc.CoredumpFilter} (want "0")
                  ProtectProc=${builtins.toJSON sc.ProtectProc} (want "invisible")
              ''}
              touch $out
            '';
          }
        ));
    };
}
