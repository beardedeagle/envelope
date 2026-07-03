set dotenv-load

stable_toolchain := "stable"

default:
    @just --list

# =============================================================================
# postmaster (Rust)
# =============================================================================

fmt:
    cargo +{{stable_toolchain}} fmt --all --manifest-path postmaster/Cargo.toml

fmt-check:
    cargo +{{stable_toolchain}} fmt --all --check --manifest-path postmaster/Cargo.toml

clippy:
    cargo +{{stable_toolchain}} clippy --all-targets --manifest-path postmaster/Cargo.toml

build:
    cargo +{{stable_toolchain}} build --manifest-path postmaster/Cargo.toml

test:
    cargo +{{stable_toolchain}} test --manifest-path postmaster/Cargo.toml

# =============================================================================
# Nix
# =============================================================================

flake-check:
    nix flake check

# =============================================================================
# Docs
# =============================================================================

docs:
    mdbook build docs

docs-serve:
    cd docs && mdbook serve

# =============================================================================
# Aggregate
# =============================================================================

ci-rust: fmt-check clippy build test

ci: ci-rust flake-check

# =============================================================================
# Dependency policy (requires cargo-deny)
# =============================================================================

deny:
    cargo deny check
