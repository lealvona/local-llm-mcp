# Changelog

All notable changes to local-llm-mcp. Dates are the day the change was pushed.

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
