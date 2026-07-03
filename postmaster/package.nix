{ lib, rustPlatform }:

let
  cargoToml = lib.importTOML ./Cargo.toml;
in

rustPlatform.buildRustPackage {
  pname = "postmaster";
  version = cargoToml.package.version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };
  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = cargoToml.package.description;
    longDescription = ''
      postmaster is a dependency-lean Rust daemon (edition 2024; pure-Rust
      crypto with no openssl, no async runtime) that serves decrypted dotenvx
      values as systemd LoadCredential AF_UNIX sources (with equivalent
      support under nix-darwin). It enables encrypted .env files to be
      treated as ordinary, world-readable Nix store artifacts while
      guaranteeing that plaintext secrets only ever appear inside
      unit-private unswappable credential ramfs.
    '';
    homepage = "https://github.com/beardedeagle/envelope";
    license = lib.licenses.mit;
    mainProgram = "postmaster";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
    # maintainers = with lib.maintainers; [ ];  # add entry in nixpkgs maintainers/maintainer-list.nix when contributing
  };
}
