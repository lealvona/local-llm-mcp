"""Cost of the identity-shape layer: find_spans on ~400 KB of mixed text, shapes on vs off.

    .venv/bin/python tools/bench_shapes.py
"""
from __future__ import annotations

import json
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from local_llm_mcp.scrub import Scrubber  # noqa: E402

rnd = random.Random(7)
WORDS = "the quick brown fox jumps over lazy dog service restarted unit active failed listening port".split()
LOG = "2026-09-08T21:{m:02d}:{s:02d} host systemd[1]: {u}.service: {w} (pid {p}) rc={rc} bytes={b}\n"
PROSE = "Dear {n},\nplease send the invoice to {a} before {d}. Regards,\n{n2}\n\n"
JSON = '{{"name": "{n}", "id": "{h}", "account number": "{acct}", "path": "/srv/apps/{w}/data"}}\n'
NAMES = ["Ada Lovelace", "Grace Hopper", "Alan Turing", "Hedy Lamarr", "Linus Torvalds"]
ADDRS = ["12 Sample Drive, Springfield, IL 62704", "P.O. Box 889, Boston, MA 02134", "10 Downing Street"]


def build(target: int) -> str:
    out: list[str] = []
    n = 0
    while n < target:
        k = rnd.random()
        if k < 0.6:
            s = LOG.format(m=rnd.randrange(60), s=rnd.randrange(60), u=rnd.choice(WORDS), w=" ".join(rnd.choices(WORDS, k=6)),
                           p=rnd.randrange(99999), rc=rnd.randrange(3), b=rnd.randrange(10**7))
        elif k < 0.8:
            s = PROSE.format(n=rnd.choice(NAMES).split()[0], a=rnd.choice(ADDRS), d=f"2026-{rnd.randrange(1,13):02d}-{rnd.randrange(1,29):02d}",
                             n2=rnd.choice(NAMES))
        else:
            s = JSON.format(n=rnd.choice(NAMES), h="%032x" % rnd.getrandbits(128), acct=rnd.randrange(10**11), w=rnd.choice(WORDS))
        out.append(s)
        n += len(s)
    return "".join(out)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        terms = Path(td) / "terms.json"
        terms.write_text(json.dumps({"terms": []}))
        text = build(400_000)
        for shapes in (False, True):
            sc = Scrubber(None, terms, shapes=shapes)
            sc.find_spans(text)  # warm
            best = min(_timed(sc, text) for _ in range(3))
            spans = sc.find_spans(text)
            print(f"shapes={'on ' if shapes else 'off'}  {len(text)/1000:.0f} KB  {best*1000:7.1f} ms  "
                  f"({best*1000/(len(text)/100_000):.1f} ms per 100 KB)  spans={len(spans)}")
    return 0


def _timed(sc: Scrubber, text: str) -> float:
    t0 = time.perf_counter()
    sc.find_spans(text)
    return time.perf_counter() - t0


if __name__ == "__main__":
    sys.exit(main())
