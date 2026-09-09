# local-llm-mcp

**A local worker model for your cloud model.** `local-llm-mcp` is an
[MCP](https://modelcontextprotocol.io) server that sits between a calling model
(Claude Code, or any MCP client) and an LLM running on your own network. The caller
hands work over; the local model does it; the caller gets back a result that is either
**sanitized** (private values replaced by stable placeholders) or **digested** (long
raw output reduced to what the caller needs). The local model keeps its **own running
memory** of the conversation and compacts it whenever the caller compacts its own.

It exists for two reasons:

1. **Privacy.** Some material must never reach a cloud model: credentials, keys,
   personal mail, contacts, addresses, account numbers, the contents of `.env` files.
   In **PII mode** the caller is told to delegate every such step; the worker reads the
   real data and the caller only ever sees `[EMAIL-1]`, `[PERSON-2]`, `[SECRET-3]`.
2. **Context economy.** A cloud model's context is expensive and finite. Most of what
   a shell command prints is noise to the caller. In **ASSIST mode** the caller is told
   to route any context-free step whose raw output would exceed the digest it needs:
   logs, test runs, listings, `git` output, `grep` results, file reads, calculations.

The server is deployment-agnostic: endpoint, key, detection rules, private terms and
attribution are all configuration. Nothing about any particular network lives in the
package.

---

## Contents

- [How it works](#how-it-works)
- [The two modes and when the caller calls](#the-two-modes-and-when-the-caller-calls)
- [Tools](#tools)
- [The privacy boundary](#the-privacy-boundary)
- [Session memory and compaction](#session-memory-and-compaction)
- [Install and wire into Claude Code](#install-and-wire-into-claude-code)
- [Configuration reference](#configuration-reference)
- [Rules file](#rules-file)
- [Private terms](#private-terms)
- [Observers](#observers)
- [Admin app](#admin-app)
- [Keeping a deployment separate from the code](#keeping-a-deployment-separate-from-the-code)
- [State on disk](#state-on-disk)
- [Testing and verification](#testing-and-verification)
- [Threat model and limits](#threat-model-and-limits)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## How it works

```
 caller (Claude Code)                        local-llm-mcp (stdio child)                   local model
 ────────────────────                        ───────────────────────────                   ───────────
 tool call ──────────────────────────────►  1. rehydrate placeholders in task/command
                                             2. gather material (run command / read files)
                                             3. register detectable values in the vault
                                             4. PII mode: entity pass ─────────────────────► "which private
                                                register what the worker found                values are here?"
                                             5. build prompt: rules + session memory +
                                                task + material ───────────────────────────► answer
                                             6. draft revises itself? one finalize call ───► committed answer
                                             7. SCRUB the answer (rules · secret shapes ·
                                                private terms · every vault value)
                                             8. store artifact (raw) + turn (scrubbed)
 digest + trailer ◄──────────────────────── 9. return
                                             ...
 PreCompact hook ── unix socket ──────────►  compact own memory (background) ─────────────► new summary
```

Every value that goes **to** the worker or the shell is rehydrated; every value that
**leaves** the server is scrubbed. That asymmetry is the whole design.

There is a second path beside the digest: **verbatim mode**. A digest paraphrases, and a
caller that needs code or configuration text cannot act on a paraphrase. With
`verbatim=true` the worker is shown numbered lines and asked only *which line ranges* the
task refers to; the server then copies those lines out of the material exactly (still
scrubbed on the way out). The model's judgement chooses the region; it never rewrites a
character of it.

## The two modes and when the caller calls

The server tells the caller, in its MCP `instructions` (returned at initialize and
again by `local_llm_set_mode`), how often and under what circumstances to call. The
active mode's rule is written first.

| | PII mode | ASSIST mode |
|---|---|---|
| **Route here** | every step that might touch private data: names, home/postal addresses, phone numbers, personal email, family details, account/card/bank numbers, credentials, API keys, tokens, vault contents, `.env`/`.secrets`/`.ssh`, password or key prompts, personal mail/messages/contacts/calendars | every step that needs no conversational context and whose raw output would exceed the digest: a direct call returning more than ~40 lines / 2 KB — logs, journals, test/build/lint runs, listings, `git log/diff/status`, `grep`/`find`, package and process lists, service/container output, API responses, long dumps; file reads and summaries; research over material; calculations; transformations; boilerplate |
| **Do directly** | anything with no private data | calls that print little or nothing (`mkdir`, `cp`, `mv`, `rm`, `touch`, `chmod`, one-line checks); files under ~40 lines; edits; anything needing exact raw bytes |
| **What comes back** | fully sanitized: placeholders for every private value; secrets are used server-side and never returned | the result edited for clarity and usefulness; only secret shapes are scrubbed |
| **When unsure** | delegate | keep exact counts/sorts in the command (`wc`, `sort -n`, `awk`, `jq`); the worker digests, it does not compute over long lists |

The mode is a server setting (`LOCAL_LLM_MCP_MODE`) and can be switched per
conversation with `local_llm_set_mode`. Claude Code truncates server instructions at
2048 characters; both texts fit.

## Tools

All tools return text; every result ends with a trailer:

```
— local-llm · pii · turn t_ef33d4 · ref a_1606e7eb · rc 0 · raw 4471 chars · finalized · local · 1.8s · scrubbed 2 EMAIL, 1 SECRET
```

`turn` is the id in the session memory, `ref` the stored raw material, `rc` the exit
code (for commands), `finalized` marks a draft folded into a committed answer.

### `local_llm_run`

Run a shell command on the host (`bash -c`, this user's privileges, stdin closed,
output capped) and receive a digest of its output. Raw output is kept as an artifact.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `command` | string | required | the command; placeholders (`[SECRET-1]`) are expanded server-side before execution |
| `task` | string | outcome, errors/warnings verbatim, key values | what to report |
| `cwd` | string | server cwd | working directory |
| `timeout_s` | int | `LOCAL_LLM_MCP_COMMAND_TIMEOUT` | kill after |
| `max_output_chars` | int | `LOCAL_LLM_MCP_MAX_OUTPUT_CHARS` | soft digest budget |
| `verbatim` | bool | `false` | quote the relevant output lines exactly instead of digesting |

A timeout or non-zero exit is reported inside the digest and in the trailer.

### `local_llm_delegate`

Hand a task to the worker over material you name: inline text, files or directories
(listed; `~` expands; missing or unreadable paths are reported inline), and/or the output
of a shell command.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `task` | string | required | what to do — what to extract, thresholds, output shape |
| `material` | string | `""` | inline text |
| `paths` | list[string] | `[]` | files or directories to read |
| `command` | string | `""` | shell command whose output is added to the material |
| `cwd` | string | `""` | base for relative paths and the command |
| `max_output_chars` | int | server default | soft answer budget |
| `verbatim` | bool | `false` | quote the relevant lines exactly instead of answering in prose |

Without material the worker answers from the task and its session memory. In verbatim
mode the result is one or more `source lines a-b:` blocks with numbered lines; ranges
that did not fit the budget are named in the trailer so you can fetch them with
`local_llm_artifact`.

### `local_llm_artifact`

Return an exact slice of a stored raw output by ref, scrubbed (fully in PII mode,
secrets only in ASSIST mode). Line mode: `line_start` / `line_end` (1-based, inclusive,
numbered output; `line_end` defaults to 200 lines). Character mode: `offset` / `limit`
(default 4000, max 20000). The trailer says where the next slice starts.

### `local_llm_status`

Mode, session key, the caller's session id, model, endpoint, turn counts, context
size, compaction count and time, placeholder counts by kind, artifact count, the
scrubbed summary, control-socket path, observer name.

### `local_llm_compact`

Compact now. Normally automatic; useful when a client has no `PreCompact` hook.

### `local_llm_set_mode`

Switch `pii` ↔ `assist` for the rest of the conversation; returns the instructions for
the new mode so the caller learns the rule in-context.

## The privacy boundary

### Placeholders

Every detected private value maps to a placeholder that is **stable for the whole
conversation**: `[EMAIL-1]` is the same address every time it appears, in every
result, artifact slice and summary. Kinds: `PERSON`, `ADDRESS`, `PHONE`, `EMAIL`,
`SSN`, `CARD`, `ACCOUNT`, `SECRET`, `PII`.

The map lives in the session vault (`placeholders.json`, mode 0600) and is never
returned. Placeholders are **re-expanded server-side** when the caller reuses them:
"reply to `[EMAIL-1]`" reaches the worker with the real address; `curl -H
'Authorization: Bearer [SECRET-1]' …` runs with the real token. The caller never holds
the value.

### Detection — layered, deterministic

| Layer | What it catches | Source |
|---|---|---|
| shape rules | emails, phone numbers, national ids, payment cards (Luhn-checked), IBANs, key prefixes, PEM headers | built in, or your rules file (`LOCAL_LLM_MCP_RULES`) |
| secret shapes | PEM blocks, JWTs, bearer headers, well-known token prefixes, `KEY=value` lines, `password: …` / `password is …` assignments; in PII mode any 32+ character mixed letters-and-digits run outside a path or URL | built in |
| private terms | the operator's own literal names, addresses, numbers — no regex knows a person's name | terms file (`LOCAL_LLM_MCP_PRIVATE_TERMS`) |
| entity pass (PII mode) | whatever private values the worker itself finds in the material: names, addresses, dates of birth, credentials it recognises in context | one extra local call per delegation; only exact substrings of the material are accepted, never a label or a variable name |
| known values | every value already in the vault, exact-matched | automatic |

Order of operations matters:

1. Everything detectable in **incoming material** is registered in the vault *before*
   the worker sees it. An echo in the answer is then caught by exact match even in a
   context no rule would recognise.
2. The worker is instructed to write placeholders itself and never quote a secret.
3. The answer is scrubbed (rules · secret shapes · terms · every vault value), then
   re-scanned; anything still detectable becomes `[REDACTED]`. A privacy boundary
   cannot rest on a model choosing to comply, so step 2 is help, not the guarantee.

### What ASSIST mode scrubs

Only secret shapes: keys, tokens, PEM blocks, password assignments. Emails, names and
phone numbers pass through, because in ASSIST mode the caller would otherwise have run
the command itself and seen the same output. The high-entropy rule is PII-only so git
SHAs and ids stay exact in ASSIST digests.

### The endpoint must be local

`LOCAL_LLM_MCP_BASE_URL` must resolve to a loopback, RFC 1918 private or CGNAT
(`100.64.0.0/10`, e.g. a tailnet) address. Anything else is refused at startup, and
there is no override. This is the one setting that is not the operator's to relax.

## Session memory and compaction

The server is a stdio child of the caller and is told nothing about which
conversation it serves. Two small hooks close that gap; the server copes without them.

**Identity.** The `SessionStart` hook walks its own process ancestry to the Claude
Code process and writes `<state>/pidmap/<pid>` = the session id; the server walks
*its* ancestry and adopts the mapped id, migrating a pid-keyed directory onto it. A
resumed conversation (new process, same id) lands on the same memory. Because the hook
can fire before the server has opened its socket, a pid-keyed session re-checks the
map on every tool call until it is named.

**Memory.** Each tool call appends a turn: kind, task, source, a scrubbed excerpt of
what the worker saw, the scrubbed result, ref, sizes, timing. Every prompt to the
worker carries the compacted summary plus as many recent turns as fit
(`LOCAL_LLM_MCP_CONTEXT_CHARS`), rehydrated for the worker's eyes only.

**Compaction.** The `PreCompact` hook sends `{"op":"compact"}` to the control socket
(`$XDG_RUNTIME_DIR/local-llm-mcp/<pid>.sock`, 0600). The server queues a compaction
and answers immediately, so the caller's own compaction is never delayed; the worker
then rewrites its summary (goals, decisions, facts with exact identifiers, placeholders
in use, open items) under a lock, and the summary is scrubbed like everything else. The
server also compacts on its own when uncompacted turns exceed
`LOCAL_LLM_MCP_AUTO_COMPACT_CHARS`, and `local_llm_compact` does it on demand.

**Control socket ops:** `compact` (queue), `session` (announce the session id),
`status`. One JSON object per line in, one out.

## Install and wire into Claude Code

Requirements: Python 3.12+, a local OpenAI-compatible chat endpoint (vLLM, llama.cpp
server, LM Studio, Ollama's OpenAI route, …).

```bash
uv tool install git+https://github.com/lealvona/local-llm-mcp    # or pipx; or uv pip install into a venv you manage
mkdir -p ~/.config/local-llm-mcp
cat > ~/.config/local-llm-mcp/env <<'EOF2'
LOCAL_LLM_MCP_MODE=assist
LOCAL_LLM_MCP_BASE_URL=http://127.0.0.1:8000/v1
LOCAL_LLM_MCP_MODEL=local
LOCAL_LLM_MCP_API_KEY_FILE=$HOME/.config/local-llm-mcp/model.key
EOF2
chmod 600 ~/.config/local-llm-mcp/env
local-llm-mcp --check            # prints effective config, rules source, session key, and probes the model
claude mcp add --scope user local-llm -- local-llm-mcp
```

Hooks — add to `~/.claude/settings.json` (both entries run the same stdlib-only
script, exit 0 always, cost milliseconds):

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}],
    "PreCompact":   [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}]
  }
}
```

`hooks/local-llm-mcp-hook.py` ships in the repo; copy it wherever you keep hooks.
Verify with `claude mcp list` (should say Connected) and, in a new session, the
`local_llm_status` tool.

Other MCP clients: run `local-llm-mcp` over stdio. Without the hooks, sessions are
keyed by the parent process id and compaction is manual or automatic-by-size.

## Configuration reference

The process environment wins over the dotenv file
(`~/.config/local-llm-mcp/env`, or `LOCAL_LLM_MCP_ENV_FILE`); the file accepts
`KEY=VALUE`, `export KEY=VALUE`, quotes, `#` comments and `$HOME`.

| Variable | Default | Meaning |
|---|---|---|
| `LOCAL_LLM_MCP_MODE` | `assist` | `pii` or `assist` |
| `LOCAL_LLM_MCP_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint; must be local |
| `LOCAL_LLM_MCP_MODEL` | `local` | model name sent to the endpoint |
| `LOCAL_LLM_MCP_API_KEY` / `LOCAL_LLM_MCP_API_KEY_FILE` | unset | bearer for the endpoint (file: one line, keep it 0600) |
| `LOCAL_LLM_MCP_THINKING` | `0` | pass `enable_thinking` to the chat template. Off is right for most local models: a reasoning budget can consume the whole `max_tokens` and return empty content |
| `LOCAL_LLM_MCP_MAX_OUTPUT_CHARS` | `2000` | default digest budget; `max_tokens` is derived from it |
| `LOCAL_LLM_MCP_MAX_TOKENS_CAP` | `8192` | ceiling on `max_tokens` |
| `LOCAL_LLM_MCP_LLM_TIMEOUT` | `300` | seconds per model call |
| `LOCAL_LLM_MCP_CHUNK_CHARS` | `24000` | material above this is processed map-reduce style |
| `LOCAL_LLM_MCP_PARALLEL_CHUNKS` | `4` | concurrent chunk calls |
| `LOCAL_LLM_MCP_MATERIAL_MAX_CHARS` | `400000` | cap on gathered material (head 70 % + tail 30 % kept, marker in between) |
| `LOCAL_LLM_MCP_CONTEXT_CHARS` | `12000` | budget for summary + recent turns in each prompt |
| `LOCAL_LLM_MCP_EXCERPT_CHARS` | `1500` | scrubbed excerpt of material kept per turn |
| `LOCAL_LLM_MCP_SUMMARY_CHARS` | `6000` | compaction target |
| `LOCAL_LLM_MCP_AUTO_COMPACT_CHARS` | `60000` | self-compaction threshold on uncompacted turns |
| `LOCAL_LLM_MCP_COMMAND_TIMEOUT` | `120` | default command timeout, seconds |
| `LOCAL_LLM_MCP_STRICT_PII` | `0` | treat every bare 10-digit run as a phone number (default: only formatted numbers or ones near phone words) |
| `LOCAL_LLM_MCP_ENTITY_PASS` | `1` | PII mode: ask the worker for the private values before answering |
| `LOCAL_LLM_MCP_RULES` | built-in | JSON rules file (see below) |
| `LOCAL_LLM_MCP_PRIVATE_TERMS` | `~/.config/local-llm-mcp/private_terms.json` | terms file (see below) |
| `LOCAL_LLM_MCP_STATE_DIR` | `~/.local/state/local-llm-mcp` | sessions, pidmap |
| `LOCAL_LLM_MCP_SOCK_DIR` | `$XDG_RUNTIME_DIR/local-llm-mcp` (else `<state>/sock`) | control sockets; AF_UNIX paths cap at 108 bytes, keep it short |
| `LOCAL_LLM_MCP_OBSERVER` | unset | `webhook`, or `module:Class` |
| `LOCAL_LLM_MCP_OBSERVER_URL` | unset | webhook target (also available to your own observer) |
| `LOCAL_LLM_MCP_OBSERVER_PATH` | unset | directory added to `sys.path` to import your observer |
| `LOCAL_LLM_MCP_SESSION` | unset | force a session key (tests, scripts) |
| `LOCAL_LLM_MCP_ADMIN_BIND` / `_ADMIN_PORT` | `127.0.0.1` / `8631` | admin app listener |
| `LOCAL_LLM_MCP_ADMIN_TOKEN` / `_ADMIN_TOKEN_FILE` | unset | bearer token the admin API requires (set it whenever the bind is not loopback) |
| `LOCAL_LLM_MCP_LOG_LEVEL` | `INFO` | stderr logging |

CLI: `local-llm-mcp [--mode pii|assist] [--session KEY] [--check]`.

## Rules file

`LOCAL_LLM_MCP_RULES` points at a JSON file that **replaces** the built-in shape
rules. The schema is deliberately compatible with a privacy-routing rules file another
tool might already maintain — other top-level keys are ignored, so one file can serve
several tools:

```json
{
  "regex_rules": [
    {"id": "email",       "pattern": "[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}"},
    {"id": "phone",       "pattern": "(?<![\\d.-])(?:\\+\\d{1,3}[ .-]?)?(?:\\(\\d{3}\\)|\\d{3})[ .-]?\\d{3}[ .-]?\\d{4}(?![\\d.-])"},
    {"id": "credit_card", "pattern": "\\b(?:\\d[ -]?){12,18}\\d\\b", "luhn": true},
    {"id": "employee_id", "pattern": "\\bEMP-\\d{6}\\b", "enabled": true}
  ]
}
```

The rule `id` decides the placeholder kind: `email`→EMAIL, `phone`→PHONE,
`us_ssn`→SSN, `credit_card`→CARD, `iban`→ACCOUNT; ids containing `key`, `token`,
`secret`, `private`, `password` or `credential`→SECRET; `mail`/`phone`/`card`/`ssn`/
`account`/`bank`/`routing` by substring; anything else→PII. The file is hot-reloaded
on change. Keep quantifiers bounded — an unbounded email pattern backtracks
quadratically on long unbroken runs.

Built-in acceptance filters apply to any rules file: a bare ten-digit `phone` match in
non-strict mode needs formatting or a nearby phone word (timestamps and ids are not
phone numbers); a `credit_card` match shaped like `YYYYMMDD-HHMMSS` is a build id, not
a card.

## Private terms

```json
{
  "terms": [
    {"kind": "PERSON",  "values": ["Jane Q. Example", "J. Example"]},
    {"kind": "ADDRESS", "values": ["12 Example Lane"]},
    {"kind": "PHONE",   "values": ["+1 555 010 0000"]},
    {"kind": "PII",     "values": []}
  ]
}
```

Case-insensitive, whole-word, longest first, hot-reloaded. Put the names, addresses and
numbers of the people this deployment protects here; keep usernames and hostnames out
(they appear in every path). This is the deterministic floor for identity that no
pattern can infer; the entity pass adds what the worker finds on top.

## Observers

Observers receive **scalar-only** events — tool name, turn id, ref, sizes, seconds,
exit code, scrub and entity counts, session key — never task text, material or
results. Three options:

- unset — no observer;
- `LOCAL_LLM_MCP_OBSERVER=webhook` with `LOCAL_LLM_MCP_OBSERVER_URL` — one JSON object
  per event: `{"event": "start"|"event"|"end", ...}`;
- `LOCAL_LLM_MCP_OBSERVER=mymodule:MyObserver` with `LOCAL_LLM_MCP_OBSERVER_PATH=/dir`
  — your own subclass, kept outside this package:

```python
# /dir/mymodule.py
from local_llm_mcp.observers import Observer

class MyObserver(Observer):
    name = "mine"
    async def start(self, info: dict) -> None: ...     # session, claude_session_id, mode, model, endpoint
    def event(self, span: str, kind: str, attrs: dict) -> None: ...   # must not block
    async def end(self, state: str = "done") -> None: ...
    @property
    def run_id(self) -> str: return ""                  # shown in local_llm_status
```

A broken or unreachable observer never fails a tool call; the server logs and continues.

## Admin app

`local-llm-mcp-admin` serves a small single-page app plus a JSON API for the PII layer —
the parts the caller never sees:

| Tab | What it shows (glance) | What it does (delve) |
|---|---|---|
| Overview | counts: terms by kind, sessions and how many are live, placeholders by kind, rules source, entity pass | each tile opens its tab |
| Terms | the private terms by kind, values masked (hover or *reveal values*) | add a term; remove one; **harvest** candidates from pasted text with the local model and tick the ones to keep |
| Sessions | one row per conversation: live dot, mode, last seen, turns, compactions, placeholder counts, artifacts, size | open a row: the placeholder vault (placeholder → kind → value), compacted memory, recent turns, artifacts; purge placeholders, delete artifacts, delete the session — refused while a server holds it |
| Scrub tester | paste text, pick a mode | the text as it would leave the server, every detected span highlighted by kind, and the placeholders that would be minted |
| Rules · Config | the shape rules in force and their source; the effective configuration (key shown as set/unset) | read-only |

```bash
local-llm-mcp-admin                 # http://127.0.0.1:8631/  (loopback, no token)
LOCAL_LLM_MCP_ADMIN_BIND=0.0.0.0 LOCAL_LLM_MCP_ADMIN_PORT=8631 \
LOCAL_LLM_MCP_ADMIN_TOKEN_FILE=~/.config/local-llm-mcp/admin.token local-llm-mcp-admin
```

It reads the same dotenv, state directory and terms file as the server (terms are
hot-reloaded, so an edit here applies to running servers at once). **It shows private
values to whoever reaches the port**: it binds to loopback by default, and when bound
wider it should sit behind a firewall *and* a token (`LOCAL_LLM_MCP_ADMIN_TOKEN` or
`_TOKEN_FILE`; the page asks once per tab). No external assets; `?demo=1` renders the
page with sample data and no server, for a look at the UI.

## Keeping a deployment separate from the code

This package carries nothing about any network. A deployment is:

| Layer | Where | Contents |
|---|---|---|
| general code | this repo | the package, hook script, tests, tools |
| runtime | a venv you install the package into (`uv tool install`, `pipx`, or `uv pip install /path/to/repo`) | re-installed to update |
| instance config | `~/.config/local-llm-mcp/` | dotenv, key files (0600, never committed), `private_terms.json`, a rules file or a pointer to one, observer plugin(s), your notes |

A minimal sync script for a checkout-based deployment:

```bash
#!/usr/bin/env bash
set -euo pipefail
REPO=~/src/local-llm-mcp; INST=~/.local/share/local-llm-mcp
[[ -d $INST/venv ]] || uv venv --python 3.12 "$INST/venv"
uv pip install --python "$INST/venv/bin/python" --reinstall-package local-llm-mcp "$REPO"
install -m 755 "$REPO/hooks/local-llm-mcp-hook.py" "$INST/hooks/local-llm-mcp-hook.py"
"$INST/venv/bin/local-llm-mcp" --check
```

Point Claude Code at `$INST/venv/bin/local-llm-mcp` and the hook copy; edit the repo,
run the script, and new sessions pick up the change. Version the config directory
privately if you like (ignore `*.key`).

## State on disk

```
~/.local/state/local-llm-mcp/
  pidmap/<pid>                      caller pid → session id (written by the SessionStart hook)
  sessions/<session>/               0700
    meta.json                       mode, counts, timestamps, identity
    context.jsonl                   turns (scrubbed); a "compaction" turn marks each summary
    summary.md                      the compacted memory (scrubbed)
    placeholders.json               the vault: placeholder ↔ value, 0600 — never leaves the host
    artifacts/a_xxxxxxxx.txt        raw material per turn, 0600 (served only through the scrub)
$XDG_RUNTIME_DIR/local-llm-mcp/<pid>.sock   control socket, 0600, removed on exit
```

Sessions are never deleted automatically; `rm -r` a session directory to forget it.

## Testing and verification

```bash
uv sync
.venv/bin/python -m pytest -q                       # scrubber, vault, rules file, dotenv, entity registration, verbatim helpers, admin API
.venv/bin/python tools/smoke.py                      # end to end over stdio against your configured model
.venv/bin/python tools/leakcheck.py ~/.secrets/app.env   # a REAL secrets file through PII mode; asserts no value leaks
```

The smoke client exercises: initialize (instructions carry the mode), tool listing,
status, a calculation, a command digest, a PII delegation (the email and password
never come back), placeholder rehydration through a shell command (an uppercased echo
comes back re-scrubbed), artifact slicing, compaction over the control socket exactly
as the hook does it, recall of a fact after compaction, verbatim quoting of a function out
of a 190-line file, line-mode artifact slicing, a command supplied to delegate, and a mode
switch.

`leakcheck.py` reads a file you name only to build the list of values to guard, runs
a fresh PII-mode server against it, and prints the digest only if none of those values
— not even a 12-character fragment — appears in it.

## Threat model and limits

**Protects against:** private values in material (files, command output, pasted
text) reaching the caller, including when the worker paraphrases, uppercases, or
quotes them; secrets in commands the caller composes from placeholders; private
values surviving into summaries and artifact slices.

**Assumes:** the host and the local model endpoint are trusted; the caller is not
malicious toward the operator (it is instructed, not sandboxed); the operator lists
the identities to protect or accepts the entity pass's recall.

**Does not protect against:** a caller that reads private files with its *own* tools
instead of delegating (the instructions say not to; nothing enforces it — put a hook in
front of those tools if you need enforcement); names and addresses that are neither in
the terms file nor recognised by the worker; secrets shaped like ordinary words with no
label; side channels such as the *length* of a rehydrated value (a command can measure
it); the worker's own logs at the endpoint.

**Known behaviours:** bare ten-digit numbers in command output are ids unless
formatted or near a phone word (`LOCAL_LLM_MCP_STRICT_PII=1` flips that); in PII mode,
long mixed alphanumeric runs (git SHAs included) become `[SECRET-n]`; a variable *name*
is never treated as a secret, its value always is; a no-thinking model that revises in
the open is folded into a committed answer by a second short call.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `claude mcp list` says `CONNECTION_CLOSED` | read Claude's log: `~/.cache/claude-cli-nodejs/<project>/mcp-logs-local-llm/*.jsonl` — it captures the server's stderr. Common: config error (bad endpoint, missing key file), or the package not importable from Claude's cwd (install it, do not rely on a working-directory import) |
| `refusing to start … not a loopback, private-network or CGNAT address` | the endpoint must be local; that is the design |
| empty answers / `spent its budget on reasoning` | keep `LOCAL_LLM_MCP_THINKING=0`, or raise `max_output_chars` |
| the caller ignores the mode rules | instructions are truncated at 2048 chars by Claude Code; check `local_llm_status` shows the mode you expect, and `local_llm_set_mode` to re-deliver the rule |
| `status` shows `session_key: pid-…` with an empty `claude_session_id` | the SessionStart hook is not installed or not on that path; the server still works, keyed by pid, and adopts the id as soon as the hook's mapping appears |
| compaction never triggers on the caller's compaction | the PreCompact hook is missing, or the socket dir differs between hook and server (`LOCAL_LLM_MCP_SOCK_DIR` must be identical in both environments); `local_llm_compact` still works |
| `socket path … near the AF_UNIX limit` | set `LOCAL_LLM_MCP_SOCK_DIR` to something short |
| the digest hides variable names as `[SECRET-n]` | a rules file rule is matching the name; names shaped `WORD_WORD` are exempt from the built-in assignment rule but not from custom rules |
| everything is `[PHONE-n]` | `LOCAL_LLM_MCP_STRICT_PII=1` on technical output; turn it off |

Logs go to stderr (Claude Code captures them); `LOCAL_LLM_MCP_LOG_LEVEL=DEBUG` for
observer traffic.

## FAQ

**Why placeholders instead of `[REDACTED]`?** So the caller can keep working: it can
address `[EMAIL-1]`, compare `[PERSON-1]` and `[PERSON-2]`, and pass `[SECRET-1]` into
a command — all without holding the value. Referential integrity survives
sanitization.

**When should I use verbatim mode?** Whenever you will *reproduce* the text rather than
act on a summary of it: a function to copy, a config block to edit, an error to quote. The
worker only chooses the lines; the bytes come from the source. A digest is for when you
need to know what something says; verbatim is for when you need to have it.

**Why does the worker get its own memory instead of the caller's?** The caller's
context is what we are trying to keep small and clean. The worker's memory is local,
cheap, and rehydrated only for the worker; the caller receives a summary only through
the scrub.

**Why one extra call in PII mode (the entity pass)?** Because a regex knows the shape of
an email, not a person's name. Asking the worker "what private values are here?" and
registering the exact substrings it names turns the model's judgement into a
deterministic guarantee — the scrub catches those strings regardless of what the
final answer says.

**Why refuse non-local endpoints outright?** The server's purpose is that private
material never leaves the network. A configuration mistake must not be able to defeat
that.

**Can I use a cloud model as the worker over a tunnel?** If it resolves to a private
address the check passes, but you would be defeating the purpose. Don't.

**Does it work without Claude Code?** Yes, with any MCP client over stdio. The hooks
are Claude Code specific; without them, sessions are keyed by parent pid and compaction
is by size or on demand.

## License

MIT — see `LICENSE`.
