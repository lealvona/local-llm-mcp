# Changelog

All notable changes to local-llm-mcp. Dates are the day the change was pushed.

## Unreleased

### The command policy

The opt-in gate decides whether the server works at all; this decides what it executes. Every command
a caller hands to `local_llm_run` — or to `local_llm_delegate`'s `command`, the same shell — runs with
the user's privileges, and a client in a bypass or auto permission mode never shows a per-tool prompt.
The server now holds its own line, in three layers.

- **Deny shapes** are refused outright, nothing run, the reason returned: privilege escalation, power
  state, filesystem and device writes, `dd of=`, recursive `rm`/`chmod`/`chown`, package installs,
  `shred`, a pipe from `curl`/`wget` into a shell, and any write under `/etc`, `/boot` or `~/.ssh`
  (reading them is untouched). Deny shapes are judged per command-line segment, so a quoted mention
  in an argument is not a match and a second command after a `;` is not hidden by the first.
- **A secret is never handed to a shell.** A command containing a placeholder that would rehydrate to
  a `[SECRET-n]` is refused. This *removes* a previously advertised behaviour — such placeholders used
  to be expanded server-side — because a command is not a boundary the server can hold.
- **An allow list** the user owns: one glob per line in `~/.config/local-llm-mcp/run-allow.txt`
  (`LOCAL_LLM_MCP_RUN_ALLOW`). Every segment of a command must match an entry, and for a multiplexer
  the subcommand is part of the shape — `git log*` is not `git push*`.
- **Everything else asks**, through the same MCP elicitation as the gate, showing the exact command and
  its working directory: refuse / run once / always allow this shape. "Always" appends the shape to the
  file. The dialog lists **refuse** first and has no default, so a client that auto-accepts a form can
  never approve a command. No allow entry and no dialog answer can exempt a deny shape.
- A client that cannot show a dialog gets the deny shapes and a trailer line saying it was not asked.
  `LOCAL_LLM_MCP_RUN_POLICY=ask|allow|off` chooses how much of this runs; a session stops asking after
  12 dialogs.
- Every decision is stamped on the turn and in the trailer (`policy: allow-list (ls*)`), counted in
  `local_llm_status.run_policy`, and shown as a chip on the session's row in the admin app.

It is deliberately not a sandbox: it reads command position, quoting and redirection well enough to
judge shapes, and does not follow a script it invokes, a variable it expands, or an alias.

### Decided
- **PyPI is not a target.** Publishing a package is a support commitment the author is not taking;
  the install path is git. `ROADMAP.md` is gone with it — both items it held are settled, one built
  and one declined.

### Fixed
- A code comment in the identity-shape layer used a real machine name from the author's own network as
  its example of a benign over-match. Replaced with an invented one. An adversarial audit found it; the
  gate did not, because a name has no shape a regex can see — which is what the hardening below is for.

### The publication gate, hardened
- **A refusal no longer prints what it caught** unless stderr is a terminal (or `--show-values`). CI
  logs are world-readable on a public repository, so a failing check could previously publish the very
  value it refused.
- **Lockfiles and every other text file are scanned.** Only binary formats are skipped.
- **Annotated tags are scanned** — message and tagger — by `pre-push` and by `--all`; `git rev-list`
  never shows either.
- New checks: **public IPv4** addresses (loopback, link-local, multicast and the RFC 5737 documentation
  ranges excluded) and **IPv6 unique-local / link-local**. Home paths now also match the root account's
  home, `/Users/…`, Windows `C:\Users\…` (single- or double-backslashed), and a path with no trailing
  slash.
- A **real subnet** such as a `/24` is now refused; RFC range constants are allowed by value, so
  documentation and code may still name them without an opt-out.
- `public:allow` may **name the check** it exempts; a bare one still exempts the shape checks, and
  **neither form can ever exempt a denylist term**.
- A denylist term containing a space also matches the underscore and hyphen forms.
- With no denylist present the output **says the name-based checks did not run** instead of "clean".
- `pre-commit` **refuses** when gitleaks is installed but cannot run, rather than recording a commit no
  secret scanner has read (`LOCAL_LLM_MCP_ALLOW_NO_GITLEAKS=1` overrides once).
- `LOCAL_LLM_MCP_DENYLIST` pointing at a file that does not exist is now an **error**, not a silent
  degrade — a typo used to disable every name-based check while still printing a pass. Leaving the
  variable unset still means "no list", which is how CI runs.
- `.gitignore` now covers the instance material the README tells you to keep beside the code — the
  dotenv, key and PEM files, the private terms, a prices override, a denylist copy — root-anchored so
  the package's own `prices.json` stays tracked.

## 0.1.0 — 2026-09-09

First tagged release. Everything below is in it.

### The boundary
- Two modes: **PII** (every private value comes back as a stable placeholder, rehydrated server-side when reused)
  and **ASSIST** (secrets always masked; account/card/id/DOB numbers masked by default; identity values shown
  only after the user says so).
- Layered deterministic detection: a rules file, built-in secret shapes, private terms, an identity-shape layer
  (addresses, labelled names, dates of birth, id numbers by shape alone), a worker entity pass over the material
  in PII mode, and — new in this release — an **answer pass** in PII mode that asks the worker what private
  values the scrubbed answer still holds and masks those too (trailer: `leak-check ok` / `leak-check FAILED`).
- Worker error text is scrubbed before it is returned.
- The **disclosure lifecycle**: the first time identity or number values appear in an ASSIST session the server
  asks the user directly through MCP elicitation; `local_llm_disclosure` records a decision made in chat;
  `LOCAL_LLM_MCP_ESCALATION=ask|auto|off`.
- The endpoint must be loopback, private-LAN or CGNAT; anything else is refused at startup.

### The opt-in gate
- The server does nothing in a session until the user turns it on: the first working tool call (or
  `local_llm_enable`) asks the user in a dialog — on / on in PII mode / off. "Off" is remembered. A client that
  cannot show a dialog is refused with the instructions for enabling it explicitly (`LOCAL_LLM_MCP_ARM=on`, or
  the admin app's per-session switch). Connect-time instructions only offer the server.
- The dialog is default-safe by construction: the answer is required, has no default, and lists "off" first,
  so a client that auto-accepts a form can never turn the server on.

### Working with the worker
- `local_llm_run` (command → digest), `local_llm_delegate` (task over files / inline material / a command),
  `local_llm_artifact` (exact slices of stored raw output), `local_llm_compact`, `local_llm_set_mode`,
  `local_llm_status` (works while off), `local_llm_enable`, `local_llm_disclosure`.
- **Verbatim mode**: the worker only locates line ranges and the server quotes them byte-exact; falls back to a
  digest when nothing matches.
- The worker keeps its own running memory of the conversation, compacted when the caller's is (PreCompact hook
  over a control socket) and when it grows large.
- **Failover** to a second local worker when the first is unreachable or answers 5xx, with a cooldown.
- Client-agnostic: any stdio MCP client; the instructions are also an MCP prompt and a resource; the session
  records its client.

### Tokens saved
- Every counted turn records what was gathered and what was returned; exact token counts come from the worker's
  own tokenizer in the background, with a characters-per-token fallback; a cross-session ledger; list prices for
  34 flagship models with a source and date per row, an override file, a staleness flag, and an admin tab.
- Per-model **tokenizer factor** (new): counts are the worker tokenizer's; each price row may carry the ratio of
  that model's tokenizer to it, applied at pricing time. Seeded at 1.3 for the Claude 4.7+ tokenizer family.

### Operating it
- Admin app: private terms, session vaults, memory and artifacts, scrub tester, prices editor, per-session gate
  and disclosure state.
- `--check` probes every configured worker; `tools/smoke.py` drives every feature over stdio, the dialogs
  included; `tools/leakcheck.py` runs a real secrets file through PII mode; `tools/piicheck.py` runs adversarial
  tasks over synthetic private data in both modes.

### Repository hygiene
- `tools/publiccheck.py` refuses deployment-specific or personal content in the tree, in staged changes, in commit
  messages and identities, and in every commit a push would publish (`--range`, `--all`), with an operator-private
  denylist reported by line number only.
- Tracked git hooks (`tools/githooks/`, installed per clone by `tools/install-hooks.sh`, local git config only)
  enforce it at pre-commit, commit-msg and pre-push; CI re-runs the tree and whole-history checks.
