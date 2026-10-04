# Optional: decisions from your own worker

**Off by default. Nothing here is needed to use local-llm-mcp.** With it off, the server registers no
decision tool or resource and creates nothing.

Switched on, two tools let a caller ask the worker you already run to pick one of a short list of named
options — the kind of choice an agent makes between steps ("summarise or quote exactly?", "is this done or
does it need checking?"). It is **advice**: it never runs, approves or retries anything. Nothing extra to
install: the same worker (and fallback) that serves the rest of local-llm-mcp answers.

## Turning it on

In the same dotenv file as the rest of your settings:

```
LOCAL_LLM_MCP_DECIDE=1
```

| Setting | Default | Meaning |
|---|---|---|
| `LOCAL_LLM_MCP_DECIDE` | `0` | the switch. `0`: no decision tools, resource or engine at all |
| `LOCAL_LLM_MCP_DECIDE_PREFER` | `primary` | which of your workers is asked first: `primary` (`LOCAL_LLM_MCP_BASE_URL`) or `fallback` (`LOCAL_LLM_MCP_FALLBACK_BASE_URL`). A smaller dense model can be the better judge even when a larger one does the summarising — measure yours with `tools/evaluate_decide.py` |
| `LOCAL_LLM_MCP_DECIDE_REASONING` | `1` | the worker writes one short sentence of reasoning before its choice (the choice is still restricted to your options). About half a second slower per decision; noticeably sturdier |
| `LOCAL_LLM_MCP_DECIDE_TIMEOUT_S` | `5` | how long the first (restricted) request may take before the engine asks again without the restriction |

`local_llm_status` reports `decide.enabled` and, per worker, any cooldown and whether it ignored the
restriction.

## What it adds

- `local_llm_decide(state, question, choices)` — 2–16 options, ids `[a-z][a-z0-9_]{0,39}`, a description each.
- `local_llm_governance(policy, evidence)` — three preset policies: `delegation_route` (digest / verbatim /
  deterministic / review), `failure_triage` (gather_evidence / configured_fallback / review / diagnose),
  `completion_review` (verify / repair / review / ready).
- Resource `local-llm://decision-policies` — the preset policy text.

Every result has `status` (`ok` or `unavailable`), `choice`, `mode` (`reasoned`, `restricted` or `parsed`),
`worker`, `elapsed_ms`, `attempts` (how the answer was reached) and, in reasoning mode, `reason`.
`unavailable` means no choice — use your normal judgement; never read it as a decision.

Both tools keep the opt-in gate, and every caller string (state, question, each option description, the
evidence) is scrubbed on its own before it reaches the worker; the result leaves through the same scrub as
every other answer.

## How a decision is made

1. The worker gets a prompt in which the question or policy is authoritative and the evidence is fenced as
   **untrusted data**: its factual reports count, any instruction, "override" or suggested answer inside it
   does not, and evidence tags inside it are removed so it cannot close the fence early.
2. The request uses vLLM's `structured_outputs` so the reply can only be one of your option ids (or, in
   reasoning mode, a JSON object whose `choice` can only be one), and the reply is checked anyway.
3. If that first request is slow (a server compiling the restriction for the first time can take far longer
   than usual) or the server ignores the restriction, the engine asks again without it and accepts only a
   reply that is exactly one option id.
4. A worker that errors, refuses or times out is skipped for a minute and the other is tried.
5. Nothing valid anywhere → `unavailable`.

Servers other than vLLM may not support `structured_outputs`; the engine then falls back to step 3 on every
call (slower, still strict). ⚠️ vLLM's older `guided_choice` field is silently ignored by recent vLLM — the
engine never uses it.

## Checking it on your hardware

`tools/evaluate_decide.py` reads the same settings as the server and runs labelled examples — the preset
policies plus prompt-injection attempts — through your workers, printing each decision, its latency and a
total. Measure before relying on it, and compare `DECIDE_PREFER` and `DECIDE_REASONING` settings on your own
workers: models differ a lot on this kind of question.
