"""Bounded-choice decisions answered by the server's own worker(s): `local_llm_decide`, the governance presets
and their catalog resource. Registered only when LOCAL_LLM_MCP_DECIDE is on; with it off the server exposes
no decision surface at all. The same arming and output boundaries as every other tool apply."""
import asyncio
import json
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from .governance import advise, catalog
from .scrub import Policy


def register(mcp, app):
    def clean(a, text):
        # Each caller string is scrubbed on its own, before any encoding: inside a JSON string a quote
        # is escaped, so `password: "..."` no longer matches a secret shape, and a masked multi-line
        # span (a PEM block) can swallow the JSON structure around it.
        if not isinstance(text, str):
            raise ValueError('state, question, evidence and choice descriptions must be text')
        a.scrubber.register_material(text, a.session.vault, policy=Policy.register(entropy=True))
        return a.outbound(text).text

    async def run(ctx, operation):
        a = app()
        allowed, notice = await a.ensure_armed(ctx, 'decision')
        if not allowed:
            return notice
        async with a.lock:
            result = await asyncio.to_thread(operation, a.decider, a)
        a.observer.event('decision', 'local_llm.decide', {'status': result['status'], 'policy': result.get('policy', 'custom'),
                                                         'mode': result.get('mode'), 'advisory_only': True})
        return a.outbound(json.dumps(result)).text

    @mcp.tool(description='Pick one of 2-16 named options for a situation, answered by the local worker. Advice only: it never runs, '
                          'approves or retries anything. Returns status ok + choice, or status unavailable and no choice (then use your '
                          'normal judgement). Option ids: lowercase, [a-z][a-z0-9_]. Requires session consent.',
              annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    async def local_llm_decide(state: str, question: str, choices: dict[str, str], ctx: Context = None) -> str:
        if not isinstance(choices, dict):
            raise ValueError('choices must map option ids to descriptions')
        def operation(engine, a):
            return engine.decide(clean(a, state), clean(a, question), {k: clean(a, v) for k, v in choices.items()}).to_dict()
        return await run(ctx, operation)

    @mcp.tool(description='Recommend delegation_route, failure_triage or completion_review from evidence, answered by the local worker. '
                          'Advice only: does not change policy, consent, permissions, leases or completion status.',
              annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    async def local_llm_governance(policy: str, evidence: str, ctx: Context = None) -> str:
        return await run(ctx, lambda engine, a: advise(engine, policy, clean(a, evidence)))

    @mcp.resource('local-llm://decision-policies', mime_type='application/json')
    def decision_policies() -> str:
        return json.dumps(catalog())
