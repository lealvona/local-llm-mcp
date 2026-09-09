"""The opt-in gate: the server does nothing in a session until the user has turned it on.

A model may be instructed to delegate work here, but it may not START doing so on its own.
The first time any working tool is called in a session, the server asks the user directly
through MCP elicitation (the client shows a dialog): turn it on for this session, turn it on in
PII mode, or keep it off. "Off" is remembered for the session and further calls return a refusal
without asking again. A client that cannot show a dialog gets a refusal that says how the user
can enable the server explicitly (``LOCAL_LLM_MCP_ARM=on`` in that client's server config, or
the admin app's session row). ``LOCAL_LLM_MCP_ARM=on`` is the user's standing approval for one
client configuration and is the only way the gate is ever passed without a dialog.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

ARM_CHOICES = ("on", "on_pii", "off")
ARM_TEXT = {
    "on": "Turn it on for this session (current mode)",
    "on_pii": "Turn it on in PII mode: every private value comes back as a placeholder",
    "off": "Keep it off for this session",
}
MAX_ARM_ASKS = 3


class EnableChoice(BaseModel):
    choice: str = Field(description="on | on_pii | off",
                        json_schema_extra={"enum": list(ARM_CHOICES), "enumNames": [ARM_TEXT[c] for c in ARM_CHOICES]})


def arm_message(mode: str, model: str, trigger: str) -> str:
    """What the human sees. The trigger names the tool the model tried, never its arguments."""
    return (
        f"local-llm-mcp is OFF in this session. The model just tried to use it ({trigger}).\n"
        f"If you turn it on, a worker model on your own network ({model}) will run commands, read files and work "
        f"over material on the model's behalf and return sanitized digests; the material stays on this machine. "
        f"Current mode: {mode.upper()} ({'everything private masked' if mode == 'pii' else 'secrets and account/id numbers masked; names shown only if you allow it'}).\n"
        f"• on — {ARM_TEXT['on']}\n• on_pii — {ARM_TEXT['on_pii']}\n• off — {ARM_TEXT['off']}\n"
        "Cancel keeps it off for now; the model may ask again later in this session."
    )


OFF_TEXT = ("[local-llm-mcp] OFF: the user chose not to turn this server on for this session. Nothing was done. "
            "Do the work yourself and do not call this server again unless the user asks for it.")

NO_DIALOG_TEXT = ("[local-llm-mcp] OFF: this server never starts without the user's explicit approval, and this client "
                  "cannot show the user a dialog. Nothing was done. The user can enable it for this client by setting "
                  "LOCAL_LLM_MCP_ARM=on in the server's environment in the client's MCP configuration, or turn on this "
                  "session from the admin app. Until then, do the work yourself.")

UNANSWERED_TEXT = ("[local-llm-mcp] OFF: the user did not answer the turn-on dialog ({action}). Nothing was done. Do the "
                   "work yourself; if the user later asks for this server, call local_llm_enable.")
