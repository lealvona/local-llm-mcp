# local-llm-mcp

An [MCP](https://modelcontextprotocol.io) server that puts a **local LLM** (any
OpenAI-compatible endpoint on your own network) behind a calling model such as
Claude Code, in one of two modes:

| Mode | The caller routes here… | What comes back |
|---|---|---|
| **PII** | every step that might touch private data: names, addresses, phone numbers, personal mail, account/card numbers, credentials, keys, tokens, `.env`/`.secrets`/`.ssh`, password prompts | a **sanitized** result: every private value replaced by a stable placeholder (`[EMAIL-1]`, `[PERSON-2]`, `[SECRET-3]`); the real values never leave the host |
| **ASSIST** | any step that needs **no broad conversational context** and whose raw output would be larger than the digest actually needed: long command output, file reads, research over material, math, transformations | the result **edited for clarity and usefulness**; only secret shapes are scrubbed |

The worker keeps its **own running context per conversation** (a turn log with
excerpts of what it saw, plus a compacted memory). When the caller's context is
compacted, a `PreCompact` hook tells the server and the **worker compacts its own
memory, itself**; it also compacts on its own when the log grows large. That
memory rides into every later prompt, so "what was the ticket number earlier?"
works across compactions.

## When the caller should call it

The MCP `instructions` (returned at initialize, and again by `local_llm_set_mode`)
carry the frequency rule for the active mode — see `CLIENT_PII` / `CLIENT_ASSIST` in
`local_llm_mcp/prompts.py`:

* **PII mode** — delegate *every* step that may touch private data; never `cat`,
  `grep` or open such material directly; work directly on anything with no private
  data; when unsure, delegate.
* **ASSIST mode** — delegate *often*: any command expected to print more than about
  40 lines / 2 KB (`local_llm_run`), any file read, summary, research or calculation
  (`local_llm_delegate`). Do **not** delegate calls that print little or nothing
  (`mkdir`, `cp`, `rm`, a one-line status check): the round trip costs more than the
  direct call. Exact counts and sorts belong in the command (`wc`, `sort`, `awk`),
  not in the worker.

Claude Code truncates server instructions at 2048 characters; the mode rule is
written first and the text stays under the cap.

## Tools

| Tool | Does |
|---|---|
| `local_llm_run` | run a shell command on this host (`bash -c`, stdin closed, output capped); the worker digests the output; raw output kept as an artifact |
| `local_llm_delegate` | task + inline material and/or file paths (directories are listed); the worker answers |
| `local_llm_artifact` | slice of a stored raw output by ref (`a_xxxxxxxx`), scrubbed |
| `local_llm_status` | mode, session identity, turns, context size, compactions, placeholder counts, the scrubbed summary |
| `local_llm_compact` | compact now (normally automatic) |
| `local_llm_set_mode` | switch `pii` ↔ `assist`; returns the instructions for the new mode |

Every result ends with a trailer: `— local-llm · <mode> · turn t_… · ref a_… · rc N · raw N chars · <model> · Ns · scrubbed …`.

## The privacy boundary

* Everything that goes **to the worker or the shell** is **rehydrated**: placeholders
  in a task or a command are replaced by their real values server-side. A caller can
  say "reply to `[EMAIL-1]`" or run `curl -H 'Authorization: Bearer [SECRET-1]' …`
  without ever holding the value.
* Everything that **leaves the server** (results, artifact slices, status, summaries)
  is **scrubbed**: fully in PII mode, secret-shapes-only in ASSIST mode.
* Detection is layered and deterministic: **shape rules** (built in, or your own
  rules file), **secret shapes** (PEM, JWT, bearer, token prefixes, `KEY=value`,
  `password: …`, and in PII mode any long high-entropy run), the operator's
  **private terms** (names, addresses — no regex knows a person's name), and in PII
  mode the **entities the worker itself finds** in the material (registered server
  side, only if they are exact substrings of the material).
* Every value detected in incoming material gets its placeholder *before* the worker
  sees it, and every vault value is exact-matched in outputs, so an echo is caught
  even in a context no rule would match. A final pass asserts nothing detectable
  survives.
* The placeholder ↔ value map (the vault) is per conversation, mode 0600, under
  `~/.local/state/local-llm-mcp/sessions/<session>/placeholders.json`. It is never
  returned.
* The model endpoint **must** be loopback, private-network or CGNAT/tailnet;
  `config.py` refuses anything else at startup, with no override.

Known limits: the deterministic scrub only knows the names and addresses it is
told (terms file) or that the worker reports (entity pass). Bare ten-digit numbers in
command output are treated as ids, not phones, unless formatted or in a phone
context; `LOCAL_LLM_MCP_STRICT_PII=1` flips that. A no-thinking model that revises
in the open is folded into a committed answer by a second short call.

## Install

```bash
uv tool install git+https://github.com/<you>/local-llm-mcp      # or: pipx install …
mkdir -p ~/.config/local-llm-mcp && $EDITOR ~/.config/local-llm-mcp/env
local-llm-mcp --check                                            # config, rules, session key, model probe
claude mcp add --scope user local-llm -- local-llm-mcp           # Claude Code, user scope
```

`~/.config/local-llm-mcp/env` is a dotenv file (`KEY=VALUE`, `$HOME` allowed; the
process environment wins over it):

```
LOCAL_LLM_MCP_MODE=assist                          # pii | assist
LOCAL_LLM_MCP_BASE_URL=http://127.0.0.1:8000/v1    # any OpenAI-compatible LOCAL endpoint
LOCAL_LLM_MCP_MODEL=local
LOCAL_LLM_MCP_API_KEY_FILE=$HOME/.config/local-llm-mcp/model.key   # or LOCAL_LLM_MCP_API_KEY
LOCAL_LLM_MCP_PRIVATE_TERMS=$HOME/.config/local-llm-mcp/private_terms.json
```

Hooks — add both to `~/.claude/settings.json`, pointing at `hooks/local-llm-mcp-hook.py`
from this repo (stdlib only, exits 0 always):

```json
"SessionStart": [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}],
"PreCompact":   [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}]
```

`SessionStart` maps the Claude process to the conversation's session id (so a
resumed conversation lands on the same context); `PreCompact` sends `compact` to the
server's control socket (`$XDG_RUNTIME_DIR/local-llm-mcp/<pid>.sock`, 0600),
fire-and-forget. A pid-keyed session also re-checks the mapping on every tool call,
so a hook that fires before the socket exists still lands.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LOCAL_LLM_MCP_MODE` | `assist` | `pii` or `assist` |
| `LOCAL_LLM_MCP_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint; must be local |
| `LOCAL_LLM_MCP_MODEL` | `local` | model name |
| `LOCAL_LLM_MCP_API_KEY` / `_API_KEY_FILE` | unset | bearer for the endpoint |
| `LOCAL_LLM_MCP_THINKING` | `0` | pass `enable_thinking` to the chat template; off keeps content from being eaten by reasoning |
| `LOCAL_LLM_MCP_RULES` | built-in | JSON rules file: `{"regex_rules": [{"id","pattern","luhn","enabled"}]}`; other keys ignored |
| `LOCAL_LLM_MCP_PRIVATE_TERMS` | `~/.config/local-llm-mcp/private_terms.json` | `{"terms": [{"kind": "PERSON", "values": [...]}, ...]}` |
| `LOCAL_LLM_MCP_STRICT_PII` | `0` | treat every bare 10-digit run as a phone number |
| `LOCAL_LLM_MCP_ENTITY_PASS` | `1` | PII mode: ask the worker for the private values first |
| `LOCAL_LLM_MCP_MAX_OUTPUT_CHARS` | `2000` | default digest budget |
| `LOCAL_LLM_MCP_CHUNK_CHARS` / `_PARALLEL_CHUNKS` | `24000` / `4` | map-reduce over large material |
| `LOCAL_LLM_MCP_MATERIAL_MAX_CHARS` | `400000` | cap on gathered material (head + tail kept) |
| `LOCAL_LLM_MCP_CONTEXT_CHARS` / `_EXCERPT_CHARS` / `_SUMMARY_CHARS` | `12000` / `1500` / `6000` | memory budgets |
| `LOCAL_LLM_MCP_AUTO_COMPACT_CHARS` | `60000` | self-compaction threshold |
| `LOCAL_LLM_MCP_COMMAND_TIMEOUT` | `120` | seconds |
| `LOCAL_LLM_MCP_STATE_DIR` / `_SOCK_DIR` | `~/.local/state/local-llm-mcp` / `$XDG_RUNTIME_DIR/local-llm-mcp` | state; sockets (AF_UNIX paths cap at 108 bytes) |
| `LOCAL_LLM_MCP_OBSERVER` | unset | `webhook`, or `module:Class` (see below) |
| `LOCAL_LLM_MCP_OBSERVER_URL` / `_OBSERVER_PATH` | unset | webhook URL; directory holding your observer module |
| `LOCAL_LLM_MCP_ENV_FILE` | `~/.config/local-llm-mcp/env` | dotenv location |
| `LOCAL_LLM_MCP_SESSION` | unset | force a session key (tests) |

### Observers

An observer receives **scalar-only** events (tool, sizes, seconds, exit code, scrub
counts — never content): `webhook` POSTs one JSON object per event; `module:Class`
loads your own `Observer` subclass (`local_llm_mcp.observers.Observer`) from
`LOCAL_LLM_MCP_OBSERVER_PATH`. That is where a deployment keeps registrar-specific
code, outside this package.

## Keeping a deployment separate from the code

This package carries nothing deployment-specific. Keep yours in
`~/.config/local-llm-mcp/` — the dotenv, key files, private terms, rules file and
observer plugin — and version that directory privately if you like. Install the
package into its own environment and re-install to update; the config layer stays
put.

## Testing

```bash
uv sync && .venv/bin/python -m pytest -q          # scrubber, vault, rules file, dotenv
.venv/bin/python tools/smoke.py                    # end to end over stdio against your model
```

The smoke client exercises initialize, tool listing, a calculation, a command digest,
a PII delegation (asserts the email and password never come back), placeholder
rehydration through a shell command, artifact slicing, compaction over the control
socket, recall after compaction, and a mode switch.

## License

MIT — see `LICENSE`.
