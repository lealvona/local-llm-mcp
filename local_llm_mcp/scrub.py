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
* **identity shapes** (PII mode only) — things that identify a person by their
  SHAPE alone, with no seed data: street addresses and PO boxes, ``City, ST 12345``,
  names introduced by an honorific, a form label, a mail header, a greeting or a
  sign-off, dates of birth, labelled account and identity numbers;
* **private terms** — the operator's own literal names, addresses and numbers
  from a terms file, because an unlabelled name has no shape;
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
# A worker sometimes writes "[CARD-<the digits>]"; masking the digits then yields "[CARD-[CARD-1]]".
_NESTED_PLACEHOLDER_RE = re.compile(r"\[([A-Z]+)-(\[(?:[A-Z]+)-\d+\])\]")
KINDS = ("PERSON", "ADDRESS", "PHONE", "EMAIL", "SSN", "CARD", "ACCOUNT", "DOB", "ID", "SECRET", "PII")

# Disclosure tiers: what a caller may be allowed to see in clear (see disclosure.py).
TIERS: dict[str, frozenset[str]] = {
    "secrets": frozenset({"SECRET"}),
    "numbers": frozenset({"SSN", "CARD", "ACCOUNT", "DOB", "ID"}),
    "identity": frozenset({"PERSON", "ADDRESS", "EMAIL", "PHONE", "PII"}),
}
_OPENABLE = TIERS["numbers"] | TIERS["identity"]


@dataclass(frozen=True)
class Policy:
    """What may leave the server in clear. Kinds in ``open`` pass; every other detectable
    value is masked. ``entropy`` runs the PII-mode high-entropy rule (off in ASSIST so git
    SHAs and ids stay exact). Secrets are never in ``open``."""

    open: frozenset[str] = frozenset()
    entropy: bool = True

    @classmethod
    def everything(cls) -> "Policy":
        return cls()

    @classmethod
    def assist(cls, identity_open: bool = False, numbers_open: bool = False) -> "Policy":
        o: set[str] = set()
        if identity_open:
            o |= TIERS["identity"]
        if numbers_open:
            o |= TIERS["numbers"]
        return cls(open=frozenset(o), entropy=False)

    @classmethod
    def secrets_only(cls) -> "Policy":
        return cls(open=_OPENABLE, entropy=False)

    @classmethod
    def register(cls, *, entropy: bool) -> "Policy":
        """Detect and vault everything, whatever may later be shown."""
        return cls(open=frozenset(), entropy=entropy)

    def masks(self, kind: str) -> bool:
        return kind not in self.open

    @property
    def fast(self) -> bool:
        """Nothing but secrets is masked: the identity layers need not run at all."""
        return _OPENABLE <= self.open

    @staticmethod
    def resolve(policy: "Policy | None", secrets_only: bool) -> "Policy":
        if policy is not None:
            return policy
        return Policy.secrets_only() if secrets_only else Policy.everything()

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


# --------------------------------------------------------------------------- identity shapes
# PII mode only. Things that identify a person by their SHAPE, with no seed data:
# street addresses and PO boxes, "City, ST 12345", names introduced by an
# honorific, a form label, a mail header, a greeting or a sign-off, dates of
# birth, and labelled account / identity numbers. Every pattern is bounded (no
# nested unbounded repeats) so the layer stays linear in the text — measured at
# ~10-15 ms per 100 KB against ~50 ms per 100 KB for the layers above it
# (tools/bench_shapes.py). An UNLABELLED name has
# no shape; those come from the terms file and the entity pass. Over-matching
# here (a product called "Mr Cabinet", a JSON "name": "Some Thing") costs a
# placeholder, never a leak, which is the fail-safe direction for PII mode.
# Off with LOCAL_LLM_MCP_SHAPES=0.

_NAME_WORD = r"[A-Z][a-z'’]{1,24}(?:-[A-Za-z][a-z'’]{1,24})?"
_NAME1 = rf"{_NAME_WORD}(?:\s+(?:[A-Z]\.\s+)?{_NAME_WORD}){{0,2}}"  # 1-3 words
_NAME2 = rf"{_NAME_WORD}(?:\s+(?:[A-Z]\.\s+)?{_NAME_WORD}){{1,3}}"  # 2-4 words
_STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Place|Pl|"
    r"Terrace|Ter|Way|Parkway|Pkwy|Highway|Hwy|Route|Rte|Trail|Trl|Square|Sq|Loop|Crescent|Cres|Close|"
    r"Gardens|Gdns|Grove|Row|Alley|Plaza|Path|Walk|Broadway|Turnpike|Tpke|Expressway|Expy)"
)
_POSTAL = r"(?:[A-Z]{2}\s+\d{5}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})"  # US zip · UK postcode
_LOCALITY = rf"(?:,?\s+{_NAME_WORD}(?:\s+{_NAME_WORD}){{0,3}},?\s+{_POSTAL}\b)?"
_UNIT = r"(?:,?\s*(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|Bldg|Building|Room|Rm|#)\.?\s*[A-Za-z0-9-]{1,8})?"
# "no. 123" · "#123" · "number 123" · ": 123" · '": "123'
_LABEL_SEP = r"(?:\s*(?i:#|no\.?|number|num\.?)\s*[:=]?|\"?\s*[:=])\s*\"?"
_MONTH = (r"(?i:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
          r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
_DATE = (r"(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}"
         rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH}\.?,?\s+\d{{4}}|{_MONTH}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}})")
_NOT_A_GREETING = (r"(?!(?:Sir|Madam|Team|All|Everyone|Everybody|Customer|Friend|Friends|Colleagues|Support|Sirs|"
                   r"There|Both|Folks|User|Users|Admin|Guest|Guests|World)\b)")
_ID_VALUE = r"([A-Z0-9][A-Z0-9 -]{3,30}[A-Z0-9])\b"

# (name, pattern, kind, value group, value must contain a digit, triggers, anchored)
# The case-insensitive label alternations are what cost time, so a labelled
# pattern is not scanned over the text: its triggers (lowercase substrings found
# with str.find on an ASCII-lowercased copy, or one cheap literal-led regex)
# locate candidates, and the pattern is then MATCHED at each hit (anchored —
# every alternative starts with one of its triggers) or searched in a short
# window around it (a label that starts before its trigger, a line-anchored
# pattern, a tail that ends the match). No triggers = scanned whole.
_Trigger = str | re.Pattern[str]
_IDENTITY: list[tuple[str, re.Pattern[str], str, int, bool, tuple[_Trigger, ...], bool]] = [
    ("street_address", re.compile(
        r"\b\d{1,6}[A-Za-z]?\s+(?:(?:[NSEW]|NE|NW|SE|SW|North|South|East|West)\.?\s+)?"
        r"(?:(?:[A-Z][A-Za-z'’.-]{1,24}|\d{1,3}(?:st|nd|rd|th))\s+){1,4}" + _STREET_SUFFIX + r"\b\.?"
        + _UNIT + _LOCALITY), "ADDRESS", 0, False, (), False),
    ("po_box", re.compile(r"\b(?i:p\.?\s?o\.?\s*box|post\s+office\s+box)\s+\d{1,8}\b" + _LOCALITY),
     "ADDRESS", 0, False, ("box",), False),
    ("city_state_zip", re.compile(
        rf"\b{_NAME_WORD}(?:\s+{_NAME_WORD}){{0,3}},\s*[A-Z]{{2}}\s+\d{{5}}(?:-\d{{4}})?\b"), "ADDRESS", 0, False,
     (re.compile(r",[ \t]*[A-Z]{2}[ \t]+\d{5}"),), False),
    ("honorific_name", re.compile(
        rf"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Sir|Dame|Rev|Sgt|Capt|Lt)\.?\s+({_NAME1})\b"), "PERSON", 1, False,
     ("mr", "ms", "miss", "mx", "dr", "prof", "sir", "dame", "rev", "sgt", "capt", "lt"), True),
    ("labelled_name", re.compile(
        r"(?i:\b(?:name|full\s+name|contact(?:\s+(?:name|person))?|customer|patient|client|tenant|guest|resident|"
        r"applicant|employee|student|bride|groom|spouse|partner|parent|guardian|owner|account\s+holder|"
        r"beneficiary|sender|recipient|passenger|driver|attn|attention)\b)\"?\s*[:=]\s*\"?(" + _NAME2 + r")\b"),
     "PERSON", 1, False,
     ("name", "full", "contact", "customer", "patient", "client", "tenant", "guest", "resident", "applicant",
      "employee", "student", "bride", "groom", "spouse", "partner", "parent", "guardian", "owner", "account",
      "beneficiary", "sender", "recipient", "passenger", "driver", "attn", "attention"), True),
    ("labelled_name_part", re.compile(
        r"(?i:\b(?:first|last|given|family|middle|maiden)\s+name|\bsurname|\bforename|\bnickname)\b\"?\s*[:=]\s*\"?("
        + _NAME1 + r")\b"), "PERSON", 1, False,
     ("first", "last", "given", "family", "middle", "maiden", "surname", "forename", "nickname"), True),
    ("mail_header_name", re.compile(
        rf"(?m)^[ \t]*(?i:From|To|Cc|Bcc|Reply-To)\s*:\s*\"?({_NAME2})\"?\s*(?=<|,|$)"), "PERSON", 1, False, (), False),
    ("greeting_name", re.compile(
        rf"(?m)\b(?:Dear|Hi|Hello|Hey|Good\s+(?:morning|afternoon|evening))[ ,]+{_NOT_A_GREETING}({_NAME1})"
        r"(?=\s*[,!.:;—–-]|\s*$)"), "PERSON", 1, False, ("dear", "hi", "hello", "hey", "good"), True),
    ("signoff_name", re.compile(
        r"(?m)^[ \t]*(?i:(?:best|kind|warm)\s+regards|regards|warmly|sincerely(?:\s+yours)?|best|all\s+the\s+best|cheers|"
        r"thanks|thank\s+you|many\s+thanks|yours(?:\s+(?:truly|sincerely|faithfully))?|love|take\s+care),?[ \t]*"
        rf"(?:\r?\n[ \t]*){{1,2}}({_NAME1})[ \t]*$"), "PERSON", 1, False,
     ("regards", "warmly", "sincerely", "best", "cheers", "thank", "yours", "love", "take care"), False),
    ("date_of_birth", re.compile(
        rf"(?i:\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|birthday|born(?:\s+on)?)\b)\"?\s*[:=]?\s*\"?({_DATE})"),
     "DOB", 1, False, ("dob", "d.o.b", "date of birth", "birth", "born"), True),
    ("labelled_ssn", re.compile(
        r"(?i:\bssn|\bsocial\s+security(?:\s+(?:no\.?|number|#))?)\"?\s*[:=]?\s*\"?(\d{3}[ -]?\d{2}[ -]?\d{4})\b"),
     "SSN", 1, True, ("ssn", "social security"), True),
    ("labelled_account", re.compile(
        r"(?i:\b(?:account|acct|routing|swift|iban|sort\s+code|(?:credit|debit|bank|payment)\s+card))\b" + _LABEL_SEP
        + _ID_VALUE), "ACCOUNT", 1, True,
     ("account", "acct", "routing", "swift", "iban", "sort code", "credit", "debit", "bank", "payment"), True),
    ("labelled_id", re.compile(
        r"(?i:\b(?:passport|driver'?s?\s+licen[cs]e|driving\s+licen[cs]e|national\s+id|national\s+insurance|"
        r"ni\s+(?:no\.?|number)|nhs|medicare|medicaid|tax\s+id|taxpayer\s+id|itin|member\s+id|policy|claim|"
        r"employee\s+id|student\s+id|patient\s+id|mrn|vin))\b" + _LABEL_SEP + _ID_VALUE), "ID", 1, True,
     ("passport", "driver", "driving", "national", "ni ", "nhs", "medicare", "medicaid", "tax", "itin", "member",
      "policy", "claim", "employee", "student", "patient", "mrn", "vin"), True),
]

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_WINDOW_BEFORE, _WINDOW_AFTER = 120, 220  # longest lead before a trigger · label + separator + longest value


def _hits(text: str, lower: str, triggers: tuple[_Trigger, ...]) -> list[int]:
    hits: set[int] = set()
    for t in triggers:
        if isinstance(t, re.Pattern):
            hits.update(m.start() for m in t.finditer(text))
            continue
        i = lower.find(t)
        while i >= 0:
            hits.add(i)
            i = lower.find(t, i + 1)
    return sorted(hits)


def _windows(hits: list[int]) -> list[tuple[int, int]]:
    """Merged [start, end) windows around trigger hits."""
    out: list[tuple[int, int]] = []
    for i in hits:
        s, e = max(0, i - _WINDOW_BEFORE), i + _WINDOW_AFTER
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def identity_spans(text: str) -> list[tuple[int, int, str, str]]:
    """Spans of the identity-shape layer: (start, end, kind, value)."""
    out: list[tuple[int, int, str, str]] = []
    seen: set[tuple[int, int]] = set()
    lower = text.translate(_ASCII_LOWER)  # length-preserving, so offsets line up
    for _name, pat, kind, grp, needs_digit, triggers, anchored in _IDENTITY:
        if not triggers:
            matches: Iterable[re.Match[str]] = pat.finditer(text)
        elif anchored:
            matches = filter(None, (pat.match(text, i) for i in _hits(text, lower, triggers)))
        else:
            matches = (m for ws, we in _windows(_hits(text, lower, triggers)) for m in pat.finditer(text, ws, we))
        for m in matches:
            value = m.group(grp)
            if not value or (m.start(grp), m.end(grp)) in seen:
                continue
            if grp != 0 and _is_reference(value):
                continue
            if needs_digit and not any(c.isdigit() for c in value):
                continue
            seen.add((m.start(grp), m.end(grp)))
            out.append((m.start(grp), m.end(grp), kind, value))
    return out


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


_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def _is_reference(value: str) -> bool:
    v = value.strip("'\"`,;)")
    low = v.lower()
    if low in _NOT_A_VALUE:
        return True
    if _ENV_NAME_RE.fullmatch(v):
        return True  # "SECRET: TELEGRAM_BOT_TOKEN" names a variable; it is not its value
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
    def __init__(self, rules_path: Path | None, terms_path: Path, strict: bool = False, shapes: bool = True):
        self.rules = Rules(rules_path)
        self.terms = PrivateTerms.load(terms_path)
        self.strict = strict
        self.shapes = shapes

    def find_spans(self, text: str, *, secrets_only: bool = False,
                   policy: Policy | None = None) -> list[tuple[int, int, str, str]]:
        """Spans to mask under ``policy`` (``secrets_only`` is the legacy spelling of
        ``Policy.secrets_only()``). Secret shapes always; the identity layers only when
        the policy masks something beyond secrets, and only the kinds it masks."""
        policy = Policy.resolve(policy, secrets_only)
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
        if policy.fast:
            spans.extend(s for s in self.rules.spans(text, self.strict) if s[2] == "SECRET")
            return spans
        spans.extend(s for s in self.rules.spans(text, self.strict) if policy.masks(s[2]))
        spans.extend(s for s in self.terms.spans(text) if policy.masks(s[2]))
        if self.shapes:
            spans.extend(s for s in identity_spans(text) if policy.masks(s[2]))
        if policy.entropy:
            for m in _ENTROPY_RE.finditer(text):
                if _looks_like_credential(m.group(0)):
                    spans.append((m.start(), m.end(), "SECRET", m.group(0)))
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

    def register_material(self, text: str, vault: Vault, *, secrets_only: bool = False,
                          policy: Policy | None = None) -> dict[str, int]:
        """Assign placeholders for everything detectable in incoming material; returns
        distinct values found per kind (the disclosure lifecycle keys off this)."""
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for _s, _e, kind, value in self.find_spans(text, secrets_only=secrets_only, policy=policy):
            if value in seen:
                continue
            seen.add(value)
            vault.placeholder_for(kind, value)
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def scrub(self, text: str, vault: Vault, *, secrets_only: bool = False,
              policy: Policy | None = None) -> ScrubResult:
        """Replace every detectable value AND every vault value the policy masks with placeholders."""
        if not text:
            return ScrubResult(text, 0, {})
        text = _NESTED_PLACEHOLDER_RE.sub(r"\2", text)  # "[CARD-[CARD-1]]" from an earlier pass or a worker
        policy = Policy.resolve(policy, secrets_only)
        spans = self.find_spans(text, policy=policy)
        # Anything the session has already seen leaks the same way whatever
        # context it appears in: exact-match every vault value too.
        for value, ph in vault.by_value.items():
            kind = vault.by_placeholder[ph]["kind"]
            if not policy.masks(kind):
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
        result = _NESTED_PLACEHOLDER_RE.sub(r"\2", "".join(out))
        # Belt and braces: nothing detectable may survive a scrub.
        leftovers = [s for s in self.find_spans(result, policy=policy)
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
            result = _NESTED_PLACEHOLDER_RE.sub(r"\2", "".join(out))
        return ScrubResult(result, replaced, kinds)
