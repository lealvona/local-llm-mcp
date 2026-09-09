"""Disclosure: which kinds of detected private values may return to the cloud caller.

Mode never decides where work runs — everything runs on the local worker either way, and a
delegation by shape ("read this PDF", "list the accounts") lands here in both modes. Mode
decides what comes BACK. Three tiers:

* **secrets** — placeholders always, in every mode, no question;
* **numbers** (SSN, card, account and id numbers, dates of birth) — placeholders by default
  in ASSIST too: a caller almost never needs the digits to do its job, it can say
  ``[ACCOUNT-1]``;
* **identity** (person, address, email, phone) — open in ASSIST once the USER says so.

The first time identity or number values appear in an ASSIST session the server asks the
human directly (MCP elicitation: the client shows a dialog while the worker keeps working):
switch the session to PII mode, continue with identity values shown, or show everything but
secrets. The answer is kept for the session and stamped into the trailer. A cancelled dialog
masks that result and asks again next time (three times at most). A client that cannot ask,
or ``LOCAL_LLM_MCP_ESCALATION=auto``, masks and tells the caller; ``=off`` opens identity
values as ASSIST always did. ``local_llm_disclosure`` sets the state when the user says so
in chat, without a dialog.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from pydantic import BaseModel, Field

from .scrub import TIERS, Policy

CHOICES = ("switch", "continue", "everything")
CHOICE_TEXT = {
    "switch": "Switch this session to PII mode: everything private becomes a placeholder, including this result",
    "continue": "Continue in ASSIST: names, addresses, emails and phones are shown to the model; "
                "secrets, account/card/id numbers and dates of birth stay masked",
    "everything": "Continue in ASSIST and show everything except secrets: account/card/id numbers and dates of birth too",
}
IDENTITY_STATES = ("undecided", "open", "masked")
NUMBER_STATES = ("open", "masked")
MAX_ASKS = 3


class DisclosureChoice(BaseModel):
    """The dialog's one field. Primitive on purpose (elicitation allows nothing else);
    ``enum``/``enumNames`` render as a single-select in clients that support them."""

    choice: str = Field(
        description="switch | continue | everything",
        json_schema_extra={"enum": list(CHOICES), "enumNames": [CHOICE_TEXT[c] for c in CHOICES]},
    )


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Disclosure:
    identity: str = "undecided"  # undecided | open | masked
    numbers: str = "masked"      # open | masked
    source: str = ""             # dialog | tool | policy | auto
    asked: int = 0
    ts: str = ""

    @classmethod
    def from_meta(cls, meta: dict, numbers_default: str = "masked") -> "Disclosure":
        raw = meta.get("disclosure") if isinstance(meta.get("disclosure"), dict) else {}
        d = cls(numbers=numbers_default if numbers_default in NUMBER_STATES else "masked")
        if raw.get("identity") in IDENTITY_STATES:
            d.identity = raw["identity"]
        if raw.get("numbers") in NUMBER_STATES:
            d.numbers = raw["numbers"]
        d.source = str(raw.get("source") or "")
        d.ts = str(raw.get("ts") or "")
        try:
            d.asked = max(0, int(raw.get("asked") or 0))
        except (TypeError, ValueError):
            d.asked = 0
        return d

    def to_meta(self) -> dict:
        return asdict(self)

    def policy(self, mode: str) -> Policy:
        """The outbound policy this state means in the given mode."""
        if mode == "pii":
            return Policy.everything()
        return Policy.assist(identity_open=(self.identity == "open"), numbers_open=(self.numbers == "open"))

    def apply(self, choice: str, source: str = "dialog") -> bool:
        """Apply a dialog/tool choice. Returns True when the session should switch to PII mode."""
        if choice not in CHOICES:
            raise ValueError(f"unknown disclosure choice {choice!r}")
        self.source = source
        self.ts = _now()
        if choice == "switch":
            return True
        self.identity = "open"
        self.numbers = "open" if choice == "everything" else "masked"
        return False

    def set(self, *, identity: str | None = None, numbers: str | None = None, source: str = "tool") -> None:
        if identity is not None:
            if identity not in IDENTITY_STATES:
                raise ValueError(f"identity must be one of {IDENTITY_STATES}")
            self.identity = identity
        if numbers is not None:
            if numbers not in NUMBER_STATES:
                raise ValueError(f"numbers must be one of {NUMBER_STATES}")
            self.numbers = numbers
        self.source = source
        self.ts = _now()

    def label(self, mode: str) -> str:
        """One short token for trailers and tables."""
        if mode == "pii":
            return "pii"
        if self.identity == "undecided":
            return "undecided"
        parts = [f"identity {self.identity}", f"numbers {self.numbers}"]
        return ", ".join(parts) + (f" ({self.source})" if self.source else "")


def detected_tiers(counts: dict[str, int]) -> dict[str, int]:
    """Openable tiers present in a detection count: ``{"identity": n, "numbers": m}`` (only nonzero)."""
    out: dict[str, int] = {}
    for tier in ("identity", "numbers"):
        n = sum(int(v) for k, v in counts.items() if k in TIERS[tier])
        if n:
            out[tier] = n
    return out


def found_text(counts: dict[str, int]) -> str:
    openable = TIERS["identity"] | TIERS["numbers"]
    return ", ".join(f"{n} {k}" for k, n in sorted(counts.items()) if k in openable and n)


def dialog_message(counts: dict[str, int], source: str) -> str:
    """What the human sees. Kinds and counts only — never a value."""
    src = source.strip()
    if len(src) > 90:
        src = src[:87] + "…"
    return (
        f"local-llm-mcp found personal data in this ASSIST session: {found_text(counts)} (in: {src}).\n"
        "The material stays on this machine either way; the choice is only about what the cloud model gets back.\n"
        f"• switch — {CHOICE_TEXT['switch']}\n"
        f"• continue — {CHOICE_TEXT['continue']}\n"
        f"• everything — {CHOICE_TEXT['everything']}\n"
        "Cancel masks this result and asks again next time."
    )
