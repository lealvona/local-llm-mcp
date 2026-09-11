"""Measure each caller model's tokenizer against the worker's, on PUBLIC text only, and set the
``tokenizer_factor`` of the price rows from the measurement instead of an assumption.

Nothing private leaves the machine: the corpus is this repository's own README, source and price
table plus synthesized directory listings, process tables and journal lines — the kinds of text a
worker digests — never a turn, an artifact or a summary. Each class is counted once with the
worker's tokenize endpoint and once against the caller model; the factor is the ratio, weighted by
class.

Two ways to count the caller side, because the first one is not always available:

``--via anthropic`` (default) uses Anthropic's ``/v1/messages/count_tokens`` — free, exact, and it
needs an API key in ``$ANTHROPIC_API_KEY`` (or ``--key-env NAME``).

``--via usage`` uses any OpenAI-compatible endpoint that reports real ``usage.prompt_tokens`` from
the model itself, and subtracts a baseline measured the same way. This is for a deployment that has
a *subscription* rather than a key — a CLI shim, for instance. It costs tokens, so keep ``--cap``
modest; the signal is thousands of tokens against a baseline stable to a handful, so a small corpus
is plenty.

⛔ Do NOT substitute a proxy's local token counter here. A gateway asked to count for a Claude model
it does not serve falls back to a *bundled* tokenizer — measured 2026-09-10: one returned Claude 2's,
giving 3.95 chars/token against the worker's 3.94, i.e. a factor of 1.0, while the real tokenizer on
the same text gave 2.92 and a factor of 1.35. A number with the wrong provenance is worse than the
assumption it replaces, because it is written down as a measurement.

    ANTHROPIC_API_KEY=… python tools/measure_tokenizer.py            # report only
    ANTHROPIC_API_KEY=… python tools/measure_tokenizer.py --write    # also write the override rows
    python tools/measure_tokenizer.py --via usage --endpoint http://127.0.0.1:8611/v1 \
        --models claude-opus-5=claude-max-opus claude-sonnet-5=claude-max-sonnet --cap 12000
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


def corpus(cap: int = CAP) -> dict[str, str]:
    code = ""
    for f in sorted((ROOT / "local_llm_mcp").glob("*.py")):
        code += f.read_text(encoding="utf-8")
        if len(code) >= cap:
            break
    return {
        "prose": (ROOT / "README.md").read_text(encoding="utf-8")[:cap],
        "code": code[:cap],
        "json": (ROOT / "local_llm_mcp" / "prices.json").read_text(encoding="utf-8")[:cap],
        "listing": synthesized_listing(cap),
    }


def anthropic_count(key: str, model: str, text: str) -> int:
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": text}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages/count_tokens", data=body, method="POST",
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(json.load(r)["input_tokens"])


# Prefixed to the baseline AND to every measured text, so it cancels in the subtraction. Its job is
# to stop an agentic harness deciding the corpus is a task and spending turns on it: prompt tokens
# accumulate across turns, so one tool call silently inflates the count for that class alone.
INSTRUCTION = "Reply with exactly: OK. Do not use any tool. Do not comment on the text below.\n\n"
PLAUSIBLE = (0.4, 3.0)  # a tokenizer ratio outside this is a measurement fault, not a finding


def usage_count(endpoint: str, model: str, text: str, key: str = "") -> int:
    """Real prompt tokens from a model that reports its own usage. Whatever the harness wraps the
    prompt in (system prompt, tool schemas) is constant per model and comes off as the baseline."""
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": INSTRUCTION + text}],
                       "max_tokens": 8}).encode()
    headers = {"content-type": "application/json", **({"authorization": f"Bearer {key}"} if key else {})}
    req = urllib.request.Request(endpoint.rstrip("/") + "/chat/completions", data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=900) as r:
        usage = json.load(r).get("usage") or {}
    n = sum(int(usage.get(k) or 0) for k in ("prompt_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    if not n:
        raise SystemExit(f"{endpoint} returned no prompt-token usage for {model}; nothing to measure against")
    return n


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
    ap.add_argument("--via", choices=("anthropic", "usage"), default="anthropic",
                    help="anthropic: the count_tokens API (needs a key). usage: any OpenAI-compatible endpoint that "
                         "reports real prompt tokens, baseline subtracted (for a subscription rather than a key)")
    ap.add_argument("--endpoint", default="", help="--via usage: the /v1 base, e.g. http://127.0.0.1:8611/v1")
    ap.add_argument("--key-env", default="ANTHROPIC_API_KEY", help="environment variable holding the API key")
    ap.add_argument("--models", nargs="*", help="model ids to measure (default: the Anthropic rows of the price "
                                                "table). --via usage takes PRICE_ROW=ENDPOINT_MODEL pairs when the "
                                                "endpoint names the model differently")
    ap.add_argument("--cap", type=int, default=CAP, help=f"characters per text class (default {CAP})")
    ap.add_argument("--baseline-samples", type=int, default=2,
                    help="--via usage: how many times to measure the per-call overhead (averaged)")
    ap.add_argument("--write", action="store_true", help="write the measured factors into the price override file")
    a = ap.parse_args()
    load_env_file()  # the deployment's dotenv, exactly as the server loads it
    key = os.environ.get(a.key_env, "")
    if a.via == "anthropic" and not key:
        print(f"no API key in ${a.key_env}", file=sys.stderr)
        return 2
    if a.via == "usage" and not a.endpoint:
        print("--via usage needs --endpoint", file=sys.stderr)
        return 2
    cfg = Config.from_env()
    prices = Prices(cfg.prices_path, cfg.caller_model)
    named = a.models or [m["model_id"] for m in prices.models if m["provider"].lower() == "anthropic"]
    # "price-row=endpoint-name", or just the one name when they agree
    models = {n.split("=", 1)[0]: n.split("=", 1)[-1] for n in named}
    texts = corpus(a.cap)
    worker_model, wc = asyncio.run(worker_counts(texts))
    print(f"worker {worker_model}: " + ", ".join(f"{k} {len(t):,} chars = {wc[k]:,} tok" for k, t in texts.items()))
    results: dict[str, dict[str, float]] = {}
    for m, remote in models.items():
        try:
            if a.via == "anthropic":
                overhead = anthropic_count(key, remote, "x")
                counts = {k: anthropic_count(key, remote, t) - overhead + 1 for k, t in texts.items()}
            else:
                samples = [usage_count(a.endpoint, remote, "x", key) for _ in range(max(1, a.baseline_samples))]
                overhead = round(sum(samples) / len(samples))
                spread = max(samples) - min(samples)
                print(f"  {m}: baseline {overhead:,} tok (spread {spread} over {len(samples)} samples)")
                counts = {k: usage_count(a.endpoint, remote, t, key) - overhead + 1 for k, t in texts.items()}
                if min(counts.values()) < 20 * spread:
                    print(f"  {m}: SKIPPED — the signal is not clear of the baseline's jitter; raise --cap")
                    continue
                # A wandering harness only ever ADDS tokens, so a re-measure takes the minimum.
                # An outlier that survives is a broken measurement and must not become a factor.
                bad = [k for k in texts if not PLAUSIBLE[0] <= counts[k] / wc[k] <= PLAUSIBLE[1]]
                for k in bad:
                    print(f"  {m}: {k} ×{counts[k] / wc[k]:.2f} is implausible — re-measuring")
                    counts[k] = min(counts[k], usage_count(a.endpoint, remote, texts[k], key) - overhead + 1)
                still = [k for k in texts if not PLAUSIBLE[0] <= counts[k] / wc[k] <= PLAUSIBLE[1]]
                if still:
                    print(f"  {m}: SKIPPED — {', '.join(still)} still implausible; this endpoint's usage is not a "
                          f"clean count for this model (an agentic harness spending turns on the corpus, most likely)")
                    continue
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
        how = "the count_tokens API" if a.via == "anthropic" else f"real usage from {a.endpoint}"
        rows = [{"model_id": m, "tokenizer_factor": round(r["factor"], 2),
                 "tokenizer_note": (f"measured {today} on {chars:,} chars of public text, {how} vs the "
                                    f"{worker_model} tokenizer: "
                                    + ", ".join(f"{k} ×{r[k]:.2f}" for k in texts) + f"; weights {WEIGHTS}")}
                for m, r in results.items()]
        prices.reload()
        doc = {"assumptions": dict(prices.assumptions), "models": rows}
        prices.save_override(doc)
        print(f"wrote {len(rows)} row(s) to {prices.override_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
