"""PII / secret detection and stable placeholder substitution.

Detection is layered, and every layer is deterministic:

* **shape rules** — regex rules for emails, phone numbers, national ids, payment
  cards (Luhn-checked), IBANs and key formats. A built-in set ships here; a JSON
  rules file (``LOCAL_LLM_MCP_RULES``) replaces it, in the schema documented on
  ``Rules`` — so a deployment that already keeps one privacy-rules file can point
  this server at the same file and have ONE definition of sensitive;
* **secret shapes** — PEM blocks, JWTs, bearer headers, well-known token prefixes,
  ``KEY=value`` lines, ``password: …`` assignments, and (PII mode only) any long
  high-entropy run;
* **private terms** — the operator's own literal names, addresses and numbers
  from a terms file, because no regex knows a person's name;
* **entities the worker found** — in PII mode the worker model is asked what
  private values the material holds; those are registered too (server side, and
  only if they are exact substrings of the material).

Every detected value maps to a placeholder that is STABLE for the session
(``[EMAIL-1]`` is the same address every time). The mapping lives only in the
session vault on this host (mode 0600); it is never returned to a caller, and it
is what lets a caller say "reply to [EMAIL-1]" in a later task.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

log = logging.getLogger("local_llm_mcp.scrub")

PLACEHOLDER_RE = re.compile(r"\[(?P<kind>[A-Z]+)-(?P<n>\d+)\]")
KINDS = ("PERSON", "ADDRESS", "PHONE", "EMAIL", "SSN", "CARD", "ACCOUNT", "SECRET", "PII")

_KIND_BY_RULE = {
    "email": "EMAIL",
    "phone": "PHONE",
    "us_ssn": "SSN",
    "credit_card": "CARD",
    "iban": "ACCOUNT",
}

# Values that look like a secret assignment but are references, not secrets.
_NOT_A_VALUE = {"none", "null", "unset", "missing", "redacted", "true", "false", "changeme", "xxx"}
_REFERENCE_PREFIXES = ("$", "${", "os.environ", "env:", "secret://", "vault://", "<", "[", "***", "/", "~/", "./", "../", "{", "%")

# (name, compiled pattern, kind, group index whose span is the value)
_BUILTIN: list[tuple[str, re.Pattern[str], str, int]] = [
    ("pem_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "SECRET", 0),
    ("pem_open", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n]*"), "SECRET", 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "SECRET", 0),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "SECRET", 0),
    ("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"), "SECRET", 1),
    ("assignment", re.compile(
        r"(?i)\b(?:password|passwd|passphrase|secret|api[_ -]?key|access[_ -]?token|auth[_ -]?token|"
        r"private[_ -]?key|client[_ -]?secret|bearer[_ -]?token|token)\b\s*[=:]\s*['\"]?([^\s'\"]{6,})"), "SECRET", 1),
    # Prose form ("the password is hunter2"): only values that look like a
    # secret, so "the secret is stored" does not lose a word.
    ("assignment_prose", re.compile(
        r"(?i)\b(?:password|passwd|passphrase|api[_ -]?key|access[_ -]?token|auth[_ -]?token|"
        r"private[_ -]?key|client[_ -]?secret)\b\s+(?:is|was|=)\s*['\"]?([^\s'\"]{6,})"), "SECRET", 1),
    ("env_secret_line", re.compile(
        r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL)[A-Z0-9_]*\s*=\s*['\"]?([^\s'\"#]{6,})"), "SECRET", 1),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "SECRET", 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "SECRET", 0),
    ("openai_style_key", re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"), "SECRET", 0),
]

# PII-mode only: any long mixed letters+digits run that is not part of a path or
# URL is treated as a credential whatever it is called. Costs some git SHAs and
# ids their exactness in PII mode, which is the fail-safe direction there; it is
# NOT applied in ASSIST mode, where secrets_only scrubbing keeps SHAs intact.
_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9_/.:\-])[A-Za-z0-9_]{32,}(?![A-Za-z0-9_/.:\-])")


def _looks_like_credential(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value) \
        and not PLACEHOLDER_RE.fullmatch(value)


_IDENTIFIER_RE = re.compile(r"[A-Z][A-Z0-9_]{2,}")

_SHELLISH_RE = re.compile(r"^[A-Za-z0-9._~:/+=-]+$")


def _kind_for_rule(rid: str) -> str:
    if rid in _KIND_BY_RULE:
        return _KIND_BY_RULE[rid]
    low = rid.lower()
    if any(t in low for t in ("key", "token", "secret", "private", "pem", "credential", "password")):
        return "SECRET"
    if "phone" in low:
        return "PHONE"
    if "mail" in low:
        return "EMAIL"
    if "card" in low:
        return "CARD"
    if "ssn" in low:
        return "SSN"
    if any(t in low for t in ("iban", "account", "routing", "bank")):
        return "ACCOUNT"
    return "PII"


def _looks_secret(value: str) -> bool:
    v = value.strip("'\"`,;).")
    return len(v) >= 12 or bool(re.search(r"[0-9_\-+/=@#$%^&*!]", v))


def _is_reference(value: str) -> bool:
    v = value.strip("'\"`,;)")
    low = v.lower()
    if low in _NOT_A_VALUE:
        return True
    if v.startswith(_REFERENCE_PREFIXES) or re.match(r"^[A-Za-z]:[\\/]", v):
        return True
    if PLACEHOLDER_RE.fullmatch(v):
        return True
    return False


# --------------------------------------------------------------------------- rules

DEFAULT_RULES: dict = {
    "regex_rules": [
        {"id": "email", "pattern": r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}"},
        {"id": "phone", "pattern": r"(?<![\d.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?![\d.-])"},
        {"id": "us_ssn", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"},
        {"id": "credit_card", "pattern": r"\b(?:\d[ -]?){12,18}\d\b", "luhn": True},
        {"id": "iban", "pattern": r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"},
        {"id": "api_secret_key", "pattern": r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"},
        {"id": "aws_access_key", "pattern": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"},
        {"id": "github_token", "pattern": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"},
        {"id": "private_key_block", "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
    ]
}

_PHONE_CONTEXT_RE = re.compile(r"\b(?:phone|telephone|mobile|cell|tel|sms|call|text(?:ing)?|whatsapp|signal)\b", re.IGNORECASE)
_TECHNICAL_DATE_ID_RE = re.compile(r"^\d{8}[-_]\d{6}$")


def luhn_ok(digits: str) -> bool:
    digits = re.sub(r"\D", "", digits)
    if not (13 <= len(digits) <= 19):
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class Rules:
    """Regex rules, built in or from a JSON file, hot-reloaded on change.

    File schema (other top-level keys are ignored, so a file that also carries
    routing settings or phrase rules for another tool works unchanged)::

        {"regex_rules": [{"id": "email", "pattern": "...", "luhn": false, "enabled": true}, ...]}

    A rule's ``id`` decides the placeholder kind (see ``_kind_for_rule``).
    """

    def __init__(self, path: Path | None):
        self.path = path
        self.mtime = -1.0
        self.source = "built-in"
        self.regex: list[tuple[str, re.Pattern[str], bool]] = []
        self._compile(DEFAULT_RULES)
        self.reload()

    def _compile(self, raw: dict) -> None:
        out = []
        for r in raw.get("regex_rules", []):
            if not r.get("enabled", True):
                continue
            try:
                out.append((str(r["id"]), re.compile(r["pattern"]), bool(r.get("luhn"))))
            except (re.error, KeyError):
                continue
        self.regex = out

    def reload(self) -> None:
        if self.path is None or not self.path.is_file():
            return
        try:
            mtime = self.path.stat().st_mtime
            if mtime == self.mtime:
                return
            self._compile(json.loads(self.path.read_text(encoding="utf-8")))
            self.mtime = mtime
            self.source = str(self.path)
        except Exception as exc:
            log.warning("rules file %s unreadable (%s); keeping the previous set", self.path, exc)

    @staticmethod
    def accept(rid: str, m: "re.Match[str]", text: str, strict: bool) -> bool:
        """Reject the well-known numeric false positives without weakening secrets."""
        candidate = m.group(0)
        if rid == "phone":
            if strict or re.search(r"[^\d]", candidate):
                return True
            context = text[max(0, m.start() - 48): m.end() + 48]
            return bool(_PHONE_CONTEXT_RE.search(context))
        if rid == "credit_card":
            return not _TECHNICAL_DATE_ID_RE.fullmatch(candidate.replace(" ", ""))
        return True

    def spans(self, text: str, strict: bool) -> list[tuple[int, int, str, str]]:
        self.reload()
        out: list[tuple[int, int, str, str]] = []
        for rid, pat, luhn in self.regex:
            kind = _kind_for_rule(rid)
            for m in pat.finditer(text):
                if luhn and not luhn_ok(m.group(0)):
                    continue
                if not self.accept(rid, m, text, strict):
                    continue
                out.append((m.start(), m.end(), kind, m.group(0)))
        return out


# --------------------------------------------------------------------------- terms


@dataclass
class PrivateTerms:
    """Operator-supplied literal terms (names, addresses, numbers) to always scrub."""

    items: list[tuple[str, re.Pattern[str], str]] = field(default_factory=list)  # (kind, pattern, value)
    path: Path | None = None
    mtime: float = -1.0

    @classmethod
    def load(cls, path: Path) -> "PrivateTerms":
        t = cls(path=path)
        t.reload()
        return t

    def reload(self) -> None:
        if self.path is None or not self.path.is_file():
            self.items = []
            return
        try:
            mtime = self.path.stat().st_mtime
            if mtime == self.mtime:
                return
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            items: list[tuple[str, re.Pattern[str], str]] = []
            for group in raw.get("terms", []):
                kind = str(group.get("kind", "PII")).upper() or "PII"
                for value in group.get("values", []):
                    value = str(value).strip()
                    if len(value) < 2:
                        continue
                    esc = re.escape(value)
                    lead = r"(?<![A-Za-z0-9])" if value[0].isalnum() else ""
                    trail = r"(?![A-Za-z0-9])" if value[-1].isalnum() else ""
                    items.append((kind, re.compile(lead + esc + trail, re.IGNORECASE), value))
            items.sort(key=lambda it: -len(it[2]))
            self.items = items
            self.mtime = mtime
        except Exception as exc:
            log.warning("private terms file %s unreadable: %s", self.path, exc)

    def spans(self, text: str) -> list[tuple[int, int, str, str]]:
        self.reload()
        out = []
        for kind, pat, value in self.items:
            for m in pat.finditer(text):
                out.append((m.start(), m.end(), kind, value))
        return out


# --------------------------------------------------------------------------- vault


class Vault:
    """Session-scoped placeholder <-> value map, persisted 0600."""

    def __init__(self, path: Path):
        self.path = path
        self.by_placeholder: dict[str, dict] = {}
        self.by_value: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        for ph, rec in data.get("placeholders", {}).items():
            self.by_placeholder[ph] = rec
            self.by_value[rec["value"]] = ph
            m = PLACEHOLDER_RE.fullmatch(ph)
            if m:
                k, n = m.group("kind"), int(m.group("n"))
                self.counters[k] = max(self.counters.get(k, 0), n)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"placeholders": self.by_placeholder}, indent=1)
        fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=str(self.path.parent))
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def placeholder_for(self, kind: str, value: str) -> str:
        value = value.strip()
        ph = self.by_value.get(value)
        if ph:
            return ph
        kind = kind.upper() if kind.upper() in KINDS else "PII"
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        ph = f"[{kind}-{n}]"
        self.by_placeholder[ph] = {"kind": kind, "value": value}
        self.by_value[value] = ph
        self._save()
        return ph

    def values(self) -> list[str]:
        return list(self.by_value.keys())

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rec in self.by_placeholder.values():
            out[rec["kind"]] = out.get(rec["kind"], 0) + 1
        return out

    def rehydrate(self, text: str) -> str:
        """Replace known placeholders with their real values (server side only)."""
        if not text or not self.by_placeholder:
            return text

        def sub(m: re.Match[str]) -> str:
            rec = self.by_placeholder.get(m.group(0))
            return rec["value"] if rec else m.group(0)

        return PLACEHOLDER_RE.sub(sub, text)


# --------------------------------------------------------------------------- scrubber


@dataclass
class ScrubResult:
    text: str
    replaced: int
    kinds: dict[str, int]

    def trailer(self) -> str:
        if not self.replaced:
            return ""
        return "scrubbed " + ", ".join(f"{n} {k}" for k, n in sorted(self.kinds.items()))


class Scrubber:
    def __init__(self, rules_path: Path | None, terms_path: Path, strict: bool = False):
        self.rules = Rules(rules_path)
        self.terms = PrivateTerms.load(terms_path)
        self.strict = strict

    def find_spans(self, text: str, *, secrets_only: bool = False) -> list[tuple[int, int, str, str]]:
        spans: list[tuple[int, int, str, str]] = []
        for name, pat, kind, grp in _BUILTIN:
            for m in pat.finditer(text):
                if m.start(grp) < 0:
                    continue
                value = m.group(grp)
                if grp != 0 and _is_reference(value):
                    continue
                if name == "assignment_prose" and not _looks_secret(value):
                    continue
                spans.append((m.start(grp), m.end(grp), kind, value))
        if not secrets_only:
            spans.extend(self.rules.spans(text, self.strict))
            spans.extend(self.terms.spans(text))
            for m in _ENTROPY_RE.finditer(text):
                if _looks_like_credential(m.group(0)):
                    spans.append((m.start(), m.end(), "SECRET", m.group(0)))
        else:
            spans.extend(s for s in self.rules.spans(text, self.strict) if s[2] == "SECRET")
        return spans

    def register_entities(self, entities: list[dict], material: str, vault: Vault) -> int:
        """Register values the worker model extracted from the material as known
        values. Only exact substrings of the material count — the model cannot
        invent a value into the vault — and the scrub then guarantees they never
        leave, whatever the model later writes."""
        n = 0
        for ent in entities or []:
            try:
                value = str(ent.get("value") or "").strip()
                kind = str(ent.get("kind") or "PII").upper()
            except AttributeError:
                continue
            if len(value) < 3 or value not in material or PLACEHOLDER_RE.fullmatch(value):
                continue
            if _IDENTIFIER_RE.fullmatch(value):
                continue  # a variable NAME (API_KEY, DB_PASSWORD) is a label, not the secret
            if kind not in KINDS:
                kind = "PII"
            if value not in vault.by_value:
                n += 1
            vault.placeholder_for(kind, value)
        return n

    def register_material(self, text: str, vault: Vault, *, secrets_only: bool = False) -> dict[str, int]:
        """Assign placeholders for everything detectable in incoming material."""
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for _s, _e, kind, value in self.find_spans(text, secrets_only=secrets_only):
            if value in seen:
                continue
            seen.add(value)
            vault.placeholder_for(kind, value)
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def scrub(self, text: str, vault: Vault, *, secrets_only: bool = False) -> ScrubResult:
        """Replace every detectable value AND every vault value with placeholders."""
        if not text:
            return ScrubResult(text, 0, {})
        spans = self.find_spans(text, secrets_only=secrets_only)
        # Anything the session has already seen leaks the same way whatever
        # context it appears in: exact-match every vault value too.
        for value, ph in vault.by_value.items():
            kind = vault.by_placeholder[ph]["kind"]
            if secrets_only and kind != "SECRET":
                continue
            if len(value) < 4:
                continue
            start = 0
            while True:
                i = text.find(value, start)
                if i < 0:
                    break
                spans.append((i, i + len(value), kind, value))
                start = i + len(value)
        if not spans:
            return ScrubResult(text, 0, {})
        # Longest-first, non-overlapping.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        out: list[str] = []
        pos = 0
        replaced = 0
        kinds: dict[str, int] = {}
        for s, e, kind, value in spans:
            if s < pos:
                continue
            out.append(text[pos:s])
            ph = vault.placeholder_for(kind, value)
            out.append(ph)
            replaced += 1
            kinds[kind] = kinds.get(kind, 0) + 1
            pos = e
        out.append(text[pos:])
        result = "".join(out)
        # Belt and braces: nothing detectable may survive a scrub.
        leftovers = [s for s in self.find_spans(result, secrets_only=secrets_only)
                     if not PLACEHOLDER_RE.fullmatch(s[3])]
        if leftovers:
            leftovers.sort(key=lambda s: (s[0], -(s[1] - s[0])))
            out, pos = [], 0
            for s, e, kind, _v in leftovers:
                if s < pos:
                    continue
                out.append(result[pos:s])
                out.append("[REDACTED]")
                replaced += 1
                kinds[kind] = kinds.get(kind, 0) + 1
                pos = e
            out.append(result[pos:])
            result = "".join(out)
        return ScrubResult(result, replaced, kinds)
