"""Tokens-saved assessment: how much of the caller's context — and money — the worker absorbed.

An ESTIMATE, deliberately simple and fully configurable:

* the caller would otherwise have READ what this server gathered (command output,
  files); it read the digest instead. **avoided input** = tokens(gathered) − tokens(returned).
  Inline material the caller pasted was already in its context and counts for nothing;
* for a delegated transformation the worker WROTE the answer the caller would otherwise
  have generated. **avoided output** = tokens(returned) × ``output_credit[kind]``
  (1.0 for a delegation, 0 for a digest of command output, 0 for verbatim quoting);
* every token that enters the caller's context is re-sent on each later model call
  until it is compacted away. **carried** = avoided input × ``context_reuse_calls``,
  priced at the cache-read rate where the model has one, else at the input rate.

Prices are LIST prices per 1M tokens (USD) for flagship models, seeded from the
providers' pricing pages on the date in ``checked``. An override file
(``LOCAL_LLM_MCP_PRICES``) replaces assumptions and adds, corrects or disables models;
the admin app edits it. Sizes are stored as characters, so changing ``chars_per_token``
re-prices history. A subscription user pays no per-token price; the dollar figure is
then the list-price equivalent of the usage kept out of the plan's limits.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger("local_llm_mcp.savings")

DEFAULT_PATH = Path(__file__).with_name("prices.json")
COUNTED_KINDS = ("run", "delegate")

_DEFAULT_ASSUMPTIONS = {
    "chars_per_token": 3.8,
    "context_reuse_calls": 8,
    "output_credit": {"run": 0.0, "delegate": 1.0, "verbatim": 0.0},
    "caller_model": "",
}


_INLINE_RE = re.compile(r"inline \((\d+) chars\)")


def gathered_chars(turn: dict) -> int:
    """Characters the server gathered for a turn. Recorded directly since the ledger
    existed; inferred for older turns: a run's material is all command output, a
    delegation's is its raw size minus the inline text the caller pasted (named in
    the source string), and nothing when the caller pasted everything."""
    if turn.get("gathered_chars") is not None:
        return max(0, int(turn.get("gathered_chars") or 0))
    kind = str(turn.get("kind") or "")
    raw = max(0, int(turn.get("raw_chars") or 0))
    if kind == "run":
        return raw
    if kind == "delegate":
        source = str(turn.get("source") or "")
        if "paths:" not in source and "command:" not in source and not source.startswith("…/") \
                and not source.startswith("/") and "inline" in source:
            return 0
        inline = sum(int(n) for n in _INLINE_RE.findall(source))
        return max(0, raw - inline)
    return 0


def _num(v, default: float = 0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if f >= 0 else default


def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".prices-", dir=str(path.parent))
    try:
        os.write(fd, json.dumps(doc, indent=1).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)


class Prices:
    """Package defaults plus an optional override file, hot-reloaded on change."""

    def __init__(self, override_path: Path | None, caller_model: str = ""):
        self.override_path = override_path
        self.caller_override = caller_model.strip()
        self.defaults = self._read(DEFAULT_PATH) or {}
        self.doc: dict = {}
        self.override_present = False
        self._stamp: float | None = -2.0
        self.reload()

    @staticmethod
    def _read(path: Path | None) -> dict | None:
        if path is None or not path.is_file():
            return None
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            return doc if isinstance(doc, dict) else None
        except Exception as exc:
            log.warning("prices file %s unreadable: %s", path, exc)
            return None

    def reload(self) -> None:
        stamp: float | None = None
        if self.override_path is not None and self.override_path.is_file():
            try:
                stamp = self.override_path.stat().st_mtime
            except OSError:
                stamp = None
        if stamp == self._stamp and self.doc:
            return
        over = self._read(self.override_path) if stamp is not None else None
        self.override_present = over is not None
        self._stamp = stamp
        self.doc = self.merge(self.defaults, over or {})

    @staticmethod
    def merge(base: dict, over: dict) -> dict:
        a = dict(_DEFAULT_ASSUMPTIONS)
        a["output_credit"] = dict(_DEFAULT_ASSUMPTIONS["output_credit"])
        for src in (base.get("assumptions") or {}, over.get("assumptions") or {}):
            for k, v in src.items():
                if k == "output_credit" and isinstance(v, dict):
                    a["output_credit"].update({str(kk): _num(vv) for kk, vv in v.items()})
                elif k in ("chars_per_token", "context_reuse_calls"):
                    a[k] = _num(v, a[k])
                elif k == "caller_model":
                    a[k] = str(v or "")
        if a["chars_per_token"] <= 0:
            a["chars_per_token"] = _DEFAULT_ASSUMPTIONS["chars_per_token"]
        models: dict[str, dict] = {}
        for src in (base.get("models") or [], over.get("models") or []):
            for m in src:
                if not isinstance(m, dict) or not str(m.get("model_id") or "").strip():
                    continue
                mid = str(m["model_id"]).strip()
                cur = dict(models.get(mid) or {})
                cur.update(m)
                models[mid] = cur
        out_models = []
        for mid, m in models.items():
            if m.get("enabled", True) is False:
                continue
            out_models.append({
                "provider": str(m.get("provider") or ""), "model_id": mid,
                "display_name": str(m.get("display_name") or mid),
                "input_per_m": _num(m.get("input_per_m")), "output_per_m": _num(m.get("output_per_m")),
                "cache_read_per_m": (None if m.get("cache_read_per_m") in (None, "") else _num(m.get("cache_read_per_m"))),
                "cache_write_per_m": (None if m.get("cache_write_per_m") in (None, "") else _num(m.get("cache_write_per_m"))),
                "context_note": str(m.get("context_note") or ""), "source_url": str(m.get("source_url") or ""),
                "checked": str(m.get("checked") or base.get("checked") or ""),
                "confidence": str(m.get("confidence") or ""),
            })
        return {"schema": 1, "checked": str(over.get("checked") or base.get("checked") or ""),
                "assumptions": a, "models": out_models}

    # ---- views -----------------------------------------------------------------

    @property
    def assumptions(self) -> dict:
        self.reload()
        return self.doc["assumptions"]

    @property
    def models(self) -> list[dict]:
        self.reload()
        return self.doc["models"]

    def model(self, model_id: str) -> dict | None:
        for m in self.models:
            if m["model_id"] == model_id:
                return m
        return None

    def caller_model(self) -> str:
        """The headline model: env override, then the file's assumption, then the first model."""
        for cand in (self.caller_override, self.assumptions.get("caller_model", "")):
            if cand and self.model(cand):
                return cand
        return self.models[0]["model_id"] if self.models else ""

    def save_override(self, doc: dict) -> dict:
        """Write the override file — assumptions plus the model rows as given, including
        ``{"model_id": …, "enabled": false}`` rows that hide a default — and return the effective doc."""
        if self.override_path is None:
            raise ValueError("no override path configured (LOCAL_LLM_MCP_PRICES)")
        doc = doc if isinstance(doc, dict) else {}
        assumptions = self.merge({}, {"assumptions": doc.get("assumptions") or {}})["assumptions"]
        models: list[dict] = []
        for m in doc.get("models") or []:
            if not isinstance(m, dict) or not str(m.get("model_id") or "").strip():
                continue
            rec: dict = {"model_id": str(m["model_id"]).strip()}
            if m.get("enabled") is False:
                rec["enabled"] = False
                models.append(rec)
                continue
            for k in ("provider", "display_name", "context_note", "source_url", "checked", "confidence"):
                if m.get(k) not in (None, ""):
                    rec[k] = str(m[k])
            for k in ("input_per_m", "output_per_m"):
                if m.get(k) not in (None, ""):
                    rec[k] = _num(m.get(k))
            for k in ("cache_read_per_m", "cache_write_per_m"):
                if k in m:
                    rec[k] = None if m.get(k) in (None, "") else _num(m.get(k))
            models.append(rec)
        out = {"schema": 1, "checked": str(doc.get("checked") or datetime.now().date().isoformat()),
               "note": "Override for local-llm-mcp price estimates; edited by the admin app or by hand. "
                       "Merged over the package defaults by model_id; enabled:false hides a default.",
               "assumptions": assumptions, "models": models}
        _write_json(self.override_path, out)
        self._stamp = -2.0
        self.reload()
        return self.doc

    def reset_override(self) -> bool:
        if self.override_path is None or not self.override_path.is_file():
            return False
        self.override_path.unlink()
        self._stamp = -2.0
        self.reload()
        return True


# --------------------------------------------------------------------------- estimates


def estimate_turn(turn: dict, assumptions: dict) -> dict:
    """Token estimate for one turn record (chars in, tokens out)."""
    kind = str(turn.get("kind") or "")
    if kind not in COUNTED_KINDS:
        return {"gathered_tokens": 0, "returned_tokens": 0, "avoided_input": 0, "avoided_output": 0, "carried": 0}
    cpt = float(assumptions.get("chars_per_token") or _DEFAULT_ASSUMPTIONS["chars_per_token"])
    gathered = gathered_chars(turn)
    returned = max(0, int(turn.get("out_chars") or 0))
    gathered_tok = round(gathered / cpt)
    returned_tok = round(returned / cpt)
    avoided_input = max(0, gathered_tok - returned_tok) if gathered else 0
    credit_key = "verbatim" if turn.get("verbatim") else kind
    credit = float((assumptions.get("output_credit") or {}).get(credit_key, 0.0) or 0.0)
    avoided_output = round(returned_tok * credit) if not turn.get("error") else 0
    reuse = float(assumptions.get("context_reuse_calls") or 0)
    return {"gathered_tokens": gathered_tok, "returned_tokens": returned_tok,
            "avoided_input": avoided_input, "avoided_output": avoided_output,
            "carried": round(avoided_input * reuse)}


def aggregate(turns: list[dict], assumptions: dict) -> dict:
    tot = {"turns": 0, "gathered_tokens": 0, "returned_tokens": 0, "avoided_input": 0, "avoided_output": 0, "carried": 0}
    for t in turns:
        if str(t.get("kind") or "") not in COUNTED_KINDS:
            continue
        e = estimate_turn(t, assumptions)
        tot["turns"] += 1
        for k in ("gathered_tokens", "returned_tokens", "avoided_input", "avoided_output", "carried"):
            tot[k] += e[k]
    return tot


def cost(agg: dict, model: dict) -> dict:
    """USD saved for one aggregate at one model's list prices."""
    inp, out = agg["avoided_input"], agg["avoided_output"]
    direct = inp * model["input_per_m"] / 1e6 + out * model["output_per_m"] / 1e6
    carry_rate = model["cache_read_per_m"] if model.get("cache_read_per_m") is not None else model["input_per_m"]
    carried = agg["carried"] * carry_rate / 1e6
    return {"direct_usd": round(direct, 4), "carried_usd": round(carried, 4), "with_carry_usd": round(direct + carried, 4)}


def costs(agg: dict, prices: Prices) -> dict[str, dict]:
    return {m["model_id"]: {"provider": m["provider"], "display_name": m["display_name"], **cost(agg, m)}
            for m in prices.models}


def fmt_tokens(n: float) -> str:
    n = float(n)
    if n >= 1e6:
        return f"{n / 1e6:.1f}M"
    if n >= 1e3:
        return f"{n / 1e3:.1f}K"
    return str(int(n))


# --------------------------------------------------------------------------- ledger


class Ledger:
    """Append-only, cross-session record of what each counted turn gathered and returned.

    Characters, not tokens, so a later change of ``chars_per_token`` re-prices history.
    Survives session purges. One JSON object per line."""

    def __init__(self, path: Path):
        self.path = path

    def append(self, session_key: str, turn: dict) -> None:
        if str(turn.get("kind") or "") not in COUNTED_KINDS:
            return
        rec = {"ts": turn.get("ts") or datetime.now().astimezone().isoformat(timespec="seconds"),
               "session": session_key, "turn": turn.get("id"), "kind": turn.get("kind"),
               "verbatim": bool(turn.get("verbatim")), "gathered_chars": gathered_chars(turn),
               "out_chars": int(turn.get("out_chars") or 0), "error": bool(turn.get("error"))}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError as exc:
            log.warning("savings ledger append failed: %s", exc)

    def records(self) -> list[dict]:
        if not self.path.is_file():
            return []
        out = []
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            return []
        return out

    def backfill(self, sessions_dir: Path) -> int:
        """Add every counted turn of every session on disk that the ledger does not
        already hold (by session + turn id). For turns older than the ledger the
        gathered size is inferred (see ``gathered_chars``). Returns the rows added."""
        have = {(r.get("session"), r.get("turn")) for r in self.records() if r.get("turn")}
        added = 0
        if not sessions_dir.is_dir():
            return 0
        for d in sorted(sessions_dir.iterdir()):
            cp = d / "context.jsonl"
            if not cp.is_file():
                continue
            try:
                lines = cp.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                try:
                    t = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(t.get("kind") or "") not in COUNTED_KINDS or not t.get("id"):
                    continue
                if (d.name, t["id"]) in have:
                    continue
                if str(t.get("result") or "").startswith("ERROR:"):
                    t = {**t, "error": True}
                self.append(d.name, t)
                have.add((d.name, t["id"]))
                added += 1
        return added

    def totals(self, assumptions: dict) -> dict:
        recs = self.records()
        agg = aggregate(recs, assumptions)
        agg["sessions"] = len({r.get("session") for r in recs})
        agg["since"] = min((r.get("ts") or "" for r in recs), default="") or None
        return agg


def report(session_turns: list[dict], ledger: Ledger, prices: Prices) -> dict:
    """The block the status tool and the admin overview show."""
    a = prices.assumptions
    session = aggregate(session_turns, a)
    all_time = ledger.totals(a)
    caller = prices.caller_model()
    per_model_session = costs(session, prices)
    per_model_all = costs(all_time, prices)
    return {
        "method": ("estimate: avoided input = gathered − returned; avoided output = returned × output_credit; "
                   "carried = avoided input × context_reuse_calls at the cache-read rate. List prices, USD."),
        "assumptions": a, "prices_checked": prices.doc.get("checked", ""),
        "caller_model": caller,
        "session": {**session, "cost": per_model_session.get(caller)},
        "all_time": {**all_time, "cost": per_model_all.get(caller)},
        "per_model": {mid: {"session_usd": per_model_session[mid]["with_carry_usd"],
                            "all_time_usd": per_model_all[mid]["with_carry_usd"],
                            "all_time_direct_usd": per_model_all[mid]["direct_usd"]}
                      for mid in per_model_all},
    }
