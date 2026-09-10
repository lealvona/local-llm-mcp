# Roadmap

Planned, not built. Each item is a design the maintainer has agreed to; order is not commitment.

Shipped since this file was written: the **command policy** for `local_llm_run` and
`local_llm_delegate(command=…)` — see "The command policy" in the README.

## PyPI

Publish `local-llm-mcp` so `uv tool install local-llm-mcp` / `pipx install local-llm-mcp` work:

1. `pyproject.toml`: classifiers, `project.urls`, `readme`, `license-files`; keep the package
   free of deployment specifics (the public-tree gate already enforces this).
2. Build with `uv build`; check with `twine check dist/*`; publish with a **trusted publisher**
   (GitHub Actions OIDC) from a `release.yml` workflow that runs only on a `v*` tag — no long-lived
   token anywhere.
3. The workflow runs the full test suite and `tools/publiccheck.py --all` first; the release
   notes come from the matching `CHANGELOG.md` section.
4. `README.md` install section: the PyPI one-liner first, the git install second.
