# Contributing to envelope

envelope provides encrypted dotenvx `.env` files as first-class Nix deployment
artifacts for NixOS and nix-darwin, together with the `postmaster` Rust
credential daemon.

External contributions are welcome.

By submitting a contribution you agree that it is licensed under the project's
[MIT license](../LICENSE) (inbound = outbound).

## Ground rules

- **The Justfile is the single source of truth.** The local git hooks (lefthook)
  and CI both call the same `just` recipes, so what passes locally passes in CI.
  Don't add a check to CI that isn't a `just` recipe.
- **The bar is enforced, not aspirational.** Clippy runs (with warnings treated
  seriously in CI), formatting is checked, Nix flake evaluation and module
  assertions are gated. CI will not go green on a warning or a failing check.
- **Real tests and evals.** New behavior (Rust or module options) should have
  coverage that would fail without the change.

## Getting set up

You need a recent stable Rust toolchain (`rustup` + the `rust-toolchain.toml`
will help), [`just`](https://just.systems), and [`lefthook`](https://lefthook.dev)
for the git hooks. Nix is required for the full flake checks.

```sh
git clone git@github.com:beardedeagle/envelope.git
cd envelope
lefthook install          # wire up the pre-commit / pre-push hooks
just --list               # see every available recipe
```

## The development loop

Run the gates before you push — they are exactly what CI runs:

```sh
just ci-rust     # fmt-check, clippy, build, test for postmaster
just ci          # ci-rust + nix flake check (and module-eval on Linux)
just docs        # mdBook build
```

See the individual recipes in the Justfile for more targeted commands
(`just fmt-check`, `just flake-check`, etc.).

## Submitting a change

1. Create a focused branch.
2. Make your change + add tests/evals where appropriate.
3. Run the full `just ci-rust && just ci`.
4. Open a PR. Use the PR template.
5. Be patient — reviews will focus on correctness, security posture (this is a
   credential/secret tool), and consistency with the existing style.

## Reporting bugs and requesting features

Please use the GitHub issue templates. For security issues, see `SECURITY.md`
and report privately (GitHub Security Advisories or the contact in that file).
