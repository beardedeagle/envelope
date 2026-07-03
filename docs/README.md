# docs/

mdBook source for the envelope documentation site.

**This site is not yet live.** The root [`README.md`](../README.md) remains
the canonical documentation until a GitHub Pages deployment is enabled (see
`.github/workflows/docs.yml` — the deploy job is commented out pending that
settings change). Page content here is carved verbatim from the README's
sections; if the two drift, trust the README.

Build locally:

```console
$ just docs         # -> docs/book
$ just docs-serve    # live-reload at http://localhost:3000
```
