"""Entry point: ``python -m local_llm_mcp [--mode pii|assist] [--check]``."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from .config import ENV_PREFIX, Config, ConfigError, load_env_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="local-llm-mcp", description="MCP server that delegates private-data or large-output work to a local LLM")
    ap.add_argument("--mode", choices=("pii", "assist"), help=f"override {ENV_PREFIX}MODE")
    ap.add_argument("--session", help=f"override the session key ({ENV_PREFIX}SESSION)")
    ap.add_argument("--transport", default="stdio", choices=("stdio",), help="MCP transport (stdio only)")
    ap.add_argument("--check", action="store_true", help="print effective config, probe the model, exit")
    args = ap.parse_args(argv)
    load_env_file()
    if args.mode:
        os.environ[ENV_PREFIX + "MODE"] = args.mode
    if args.session:
        os.environ[ENV_PREFIX + "SESSION"] = args.session

    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        print(f"local-llm-mcp: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(stream=sys.stderr, level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s local-llm-mcp %(levelname)s %(name)s: %(message)s")

    if args.check:
        return _check(cfg)

    from .server import build

    build(cfg).run(transport=args.transport)
    return 0


def _check(cfg: Config) -> int:
    from .llm import LLMError, LocalLLM
    from .scrub import Scrubber
    from .session import Session

    print(json.dumps(cfg.public(), indent=1), file=sys.stderr)
    from .observers import load_observer

    scrub = Scrubber(cfg.rules_path, cfg.private_terms_path, strict=cfg.strict_pii, shapes=cfg.shapes)
    print(f"rules: {scrub.rules.source} ({len(scrub.rules.regex)} regex rules); private terms: {len(scrub.terms.items)}; "
          f"identity shapes: {'on' if scrub.shapes else 'off'}; observer: {load_observer(cfg).name}", file=sys.stderr)
    from .savings import Prices
    prices = Prices(cfg.prices_path, cfg.caller_model)
    print(f"prices: {len(prices.models)} models (checked {prices.doc.get('checked')}), headline {prices.caller_model() or '-'}, "
          f"override {'present' if prices.override_present else 'absent'} at {cfg.prices_path}", file=sys.stderr)
    s = Session(cfg)
    print(f"session: key={s.key} claude_pid={s.claude_pid} dir={s.dir}", file=sys.stderr)

    async def probe() -> int:
        llm = LocalLLM(cfg)
        try:
            text, usage = await llm.chat("Reply with exactly: OK", "ping", max_tokens=16)
            print(f"model {cfg.model} at {cfg.base_url}: {text!r} usage={usage}", file=sys.stderr)
            return 0
        except LLMError as exc:
            print(f"model probe FAILED: {exc}", file=sys.stderr)
            return 1
        finally:
            await llm.aclose()

    return asyncio.run(probe())


if __name__ == "__main__":
    sys.exit(main())
