# Roadmap

Planned, not built. Each item is a design the maintainer has agreed to; order is not commitment.

## Command policy for `local_llm_run`

The opt-in gate covers *turning the server on*. After that, every command the model chooses runs
with the user's privileges, and a client in a bypass or auto permission mode never shows the user
a per-tool prompt. The server should hold its own line:

1. **Built-in deny shapes** — refused outright, with the reason in the result and nothing run:
   `rm -r*`, `mkfs`, `dd of=`, `> /dev/`, `shutdown|reboot|halt`, `sudo`/`doas`, `chmod -R`,
   `chown -R`, package installs, `curl|wget … | sh`, writes to `~/.ssh`, `/etc`, `/boot`, and any
   command containing a placeholder that would rehydrate to a **secret** (a secret is never
   handed to a shell).
2. **An allow list in the instance config** (`LOCAL_LLM_MCP_RUN_ALLOW`, one glob per line):
   commands matching it run without a question — the operator's standing approval for the shapes
   they delegate every day (`git log*`, `journalctl*`, `ls*`, `rg*`, `pytest*` …).
3. **Everything else asks** — the same MCP elicitation the gate uses, showing the exact command,
   with *run once / always allow this shape / refuse*. "Always" appends to the allow list.
   A client that cannot ask gets the deny-shape check only, plus a trailer line saying so.
4. Every decision is recorded on the turn (`policy: allow-list | asked:run | refused:…`) and shown
   in the admin app; the status block carries the counts.

Non-goals: parsing shell semantics fully (the deny list is shapes, not a sandbox), or replacing
the client's own permission system where it exists.

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
