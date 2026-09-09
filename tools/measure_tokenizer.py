"""Measure each caller model's tokenizer against the worker's, on PUBLIC text only, and set the
``tokenizer_factor`` of the price rows from the measurement instead of an assumption.

Nothing private leaves the machine: the corpus is this repository's own README, source and price
table plus synthesized directory listings, process tables and journal lines — the kinds of text a
worker digests — never a turn, an artifact or a summary. Each class is counted once with the
worker's tokenize endpoint and once with Anthropic's token-count endpoint (free, needs an API key
in ``$ANTHROPIC_API_KEY`` or ``--key-env NAME``); the factor is the ratio, weighted by class.

    ANTHROPIC_API_KEY=… python tools/measure_tokenizer.py            # report only
    ANTHROPIC_API_KEY=… python tools/measure_tokenizer.py --write    # also write the override rows
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from local_llm_mcp.config import Config, load_env_file  # noqa: E402
from local_llm_mcp.llm import LocalLLM  # noqa: E402
from local_llm_mcp.savings import Prices  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = 30_000
WEIGHTS = {"listing": 0.45, "code": 0.30, "prose": 0.15, "json": 0.10}  # what delegated material mostly is
WORDS = ("alpha beta gamma delta kernel module service worker cache index build report notes draft final "
         "archive backup config data image video audio model tokens vault ledger prices admin hooks tests").split()


def synthesized_listing(n_chars: int) -> str:
    rng = random.Random(7)
    out: list[str] = []
    while sum(len(x) + 1 for x in out) < n_chars:
        kind = rng.choice(("ls", "ps", "journal", "log"))
        if kind == "ls":
            out.append(f"-rw-r--r-- 1 user user {rng.randint(100, 9_999_999):>9} Sep {rng.randint(1, 30):2d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d} "
                       f"{rng.choice(WORDS)}-{rng.choice(WORDS)}.{rng.choice(('py', 'json', 'log', 'txt', 'md'))}")
        elif kind == "ps":
            out.append(f"user {rng.randint(1000, 999999):>8} {rng.random() * 9:4.1f} {rng.random() * 3:4.1f} {rng.randint(10000, 999999):>8} "
                       f"{rng.randint(1000, 99999):>6} ?  Ssl  {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d} {rng.randint(0, 59):>4}:{rng.randint(0, 59):02d} "
                       f"/usr/bin/{rng.choice(WORDS)} --{rng.choice(WORDS)}={rng.choice(WORDS)}")
        elif kind == "journal":
            out.append(f"Sep {rng.randint(1, 30):02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} host "
                       f"{rng.choice(WORDS)}[{rng.randint(100, 99999)}]: {rng.choice(('Started', 'Stopped', 'Reloaded', 'Failed'))} "
                       f"{rng.choice(WORDS)} {rng.choice(WORDS)} ({rng.randint(1, 500)} ms)")
        else:
            out.append(f"2026-09-{rng.randint(1, 30):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} "
                       f"{rng.choice(('INFO', 'WARN', 'DEBUG', 'ERROR'))} {rng.choice(WORDS)}.{rng.choice(WORDS)}: {rng.choice(WORDS)}={rng.randint(0, 99999)} "
                       f"{rng.choice(WORDS)}={rng.choice(('true', 'false', 'null'))} took {rng.random() * 100:.2f}s")
    return "\n".join(out)[:n_chars]


def corpus() -> dict[str, str]:
    code = ""
    for f in sorted((ROOT / "local_llm_mcp").glob("*.py")):
        code += f.read_text(encoding="utf-8")
        if len(code) >= CAP:
            break
    return {
        "prose": (ROOT / "README.md").read_text(encoding="utf-8")[:CAP],
        "code": code[:CAP],
        "json": (ROOT / "local_llm_mcp" / "prices.json").read_text(encoding="utf-8")[:CAP],
        "listing": synthesized_listing(CAP),
    }


def anthropic_count(key: str, model: str, text: str) -> int:
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": text}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages/count_tokens", data=body, method="POST",
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(json.load(r)["input_tokens"])


async def worker_counts(texts: dict[str, str]) -> tuple[str, dict[str, int]]:
    cfg = Config.from_env()  # the dotenv was loaded by main()
    llm = LocalLLM(cfg)
    out = {}
    for k, t in texts.items():
        n = await llm.count_tokens(t)
        if n is None:
            raise SystemExit("the worker offers no tokenize endpoint; nothing to measure against")
        out[k] = int(n)
    return cfg.model, out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--key-env", default="ANTHROPIC_API_KEY", help="environment variable holding the Anthropic API key")
    ap.add_argument("--models", nargs="*", help="model ids to measure (default: the Anthropic rows of the price table)")
    ap.add_argument("--write", action="store_true", help="write the measured factors into the price override file")
    a = ap.parse_args()
    load_env_file()  # the deployment's dotenv, exactly as the server loads it
    key = os.environ.get(a.key_env, "")
    if not key:
        print(f"no API key in ${a.key_env}", file=sys.stderr)
        return 2
    cfg = Config.from_env()
    prices = Prices(cfg.prices_path, cfg.caller_model)
    models = a.models or [m["model_id"] for m in prices.models if m["provider"].lower() == "anthropic"]
    texts = corpus()
    worker_model, wc = asyncio.run(worker_counts(texts))
    base = {m: None for m in models}
    print(f"worker {worker_model}: " + ", ".join(f"{k} {len(t):,} chars = {wc[k]:,} tok" for k, t in texts.items()))
    results: dict[str, dict[str, float]] = {}
    for m in models:
        try:
            overhead = anthropic_count(key, m, "x")
            counts = {k: anthropic_count(key, m, t) - overhead + 1 for k, t in texts.items()}
        except urllib.error.HTTPError as e:
            print(f"  {m}: HTTP {e.code} {e.read().decode('utf-8', 'replace')[:160]}")
            continue
        ratios = {k: counts[k] / wc[k] for k in texts}
        combined = sum(WEIGHTS[k] * ratios[k] for k in texts)
        results[m] = {**ratios, "factor": combined}
        print(f"  {m:<28} " + "  ".join(f"{k} ×{ratios[k]:.3f}" for k in texts) + f"  → factor {combined:.2f}")
    if not results:
        return 1
    print("weights:", WEIGHTS)
    if a.write:
        if prices.override_path is None:
            print("no override path configured (LOCAL_LLM_MCP_PRICES); nothing written", file=sys.stderr)
            return 2
        today = date.today().isoformat()
        chars = sum(len(t) for t in texts.values())
        rows = [{"model_id": m, "tokenizer_factor": round(r["factor"], 2),
                 "tokenizer_note": (f"measured {today} on {chars:,} chars of public text vs the {worker_model} tokenizer: "
                                    + ", ".join(f"{k} ×{r[k]:.2f}" for k in texts) + f"; weights {WEIGHTS}")}
                for m, r in results.items()]
        prices.reload()
        doc = {"assumptions": dict(prices.assumptions), "models": rows}
        prices.save_override(doc)
        print(f"wrote {len(rows)} row(s) to {prices.override_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
