# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-03

### Added

- Initial release of `postmaster`: a dependency-lean Rust daemon (edition 2024,
  pure-Rust crypto, rustix syscalls) that serves decrypted dotenvx values as
  systemd `LoadCredential` AF_UNIX sources (and equivalent support on nix-darwin).
- NixOS and nix-darwin modules under `services.dotenvx` for three injection
  modes (`env`, `files`, `credentials`).
- Flake providing `packages.postmaster`, overlays, and `nixosModules` /
  `darwinModules`.
- mdBook documentation covering quick start, key provisioning, threat model,
  operational notes, and macOS specifics.
- Hardened service configuration (no core dumps, ProtectProc, etc.).
- CI for Rust (fmt, clippy `-D warnings`, build, test) and Nix (flake check
  across systems + module eval assertions).

[0.1.0]: https://github.com/beardedeagle/envelope/releases/tag/v0.1.0
