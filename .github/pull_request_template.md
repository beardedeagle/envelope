## Summary

<!-- What does this PR change, and why? Reference any related issue, e.g. "Closes #123". -->

## How was this verified?

<!-- Describe how you tested the change and paste the relevant command output. -->

## Checklist

- [ ] The diff is focused -- one logical change.
- [ ] `just ci-rust` passes locally (formatting, clippy, build, test).
- [ ] `just ci` passes (includes `nix flake check` and module eval).
- [ ] New or changed behavior is covered by a test (or NixOS/nix-darwin eval) that would fail without this change.
- [ ] Documentation changes: `just docs` succeeds and content is accurate.
- [ ] Commit messages have an imperative subject and explain *why*.
- [ ] I have read the contributing guidelines.
