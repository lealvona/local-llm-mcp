"""The opt-in gate: nothing runs until the user says yes, and only the user can say it."""
import asyncio
import types

from local_llm_mcp.arming import NO_DIALOG_TEXT, OFF_TEXT, EnableChoice, arm_message
from local_llm_mcp.config import Config
from local_llm_mcp.server import App
from tests.test_delegate import make_app


class FakeCtx:
    """Just enough of a FastMCP Context: a client that can (or cannot) show a dialog, and an answer."""

    def __init__(self, can_ask: bool, action: str = "accept", choice: str = "on"):
        cap = types.SimpleNamespace(elicitation=object() if can_ask else None)
        params = types.SimpleNamespace(capabilities=cap, clientInfo=types.SimpleNamespace(name="fake", version="1"))
        self.session = types.SimpleNamespace(client_params=params)
        self.action, self.choice = action, choice
        self.messages: list[str] = []

    async def elicit(self, message, schema):
        self.messages.append(message)
        data = schema(choice=self.choice) if self.action == "accept" else None
        return types.SimpleNamespace(action=self.action, data=data)


def gate(app: App, ctx, trigger="local_llm_run"):
    return asyncio.run(app.ensure_armed(ctx, trigger))


def test_off_until_asked_and_client_without_dialog_is_refused(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    assert app.session.armed_state() is None
    on, text = gate(app, None)
    assert not on and text == NO_DIALOG_TEXT and app.session.armed_state() is None
    on, text = gate(app, FakeCtx(can_ask=False))
    assert not on and "LOCAL_LLM_MCP_ARM=on" in text


def test_dialog_on_returns_the_rules_and_is_remembered(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    ctx = FakeCtx(can_ask=True, choice="on")
    on, text = gate(app, ctx, "local_llm_delegate")
    assert on and "turned this server on" in text and "ACTIVE MODE: ASSIST" in text
    assert "local_llm_delegate" in ctx.messages[0] and "OFF in this session" in ctx.messages[0]
    assert app.session.armed_state() == "on" and app.session.meta["armed"]["source"] == "dialog"
    on, text = gate(app, FakeCtx(can_ask=True, choice="off"))  # already on: no second dialog, no text
    assert on and text == "" and app.session.armed_state() == "on"


def test_dialog_on_pii_switches_mode(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    on, text = gate(app, FakeCtx(can_ask=True, choice="on_pii"))
    assert on and app.mode == "pii" and "ACTIVE MODE: PII" in text


def test_dialog_off_is_remembered_and_never_reasked(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    ctx = FakeCtx(can_ask=True, choice="off")
    on, text = gate(app, ctx)
    assert not on and text == OFF_TEXT and app.session.armed_state() == "off"
    ctx2 = FakeCtx(can_ask=True, choice="on")
    on, text = gate(app, ctx2)
    assert not on and text == OFF_TEXT and ctx2.messages == []  # not asked again


def test_unanswered_dialog_asks_again_then_gives_up(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    for i in range(3):
        on, text = gate(app, FakeCtx(can_ask=True, action="cancel"))
        assert not on and "did not answer" in text and app.session.armed_state() is None
    on, text = gate(app, FakeCtx(can_ask=True, action="cancel"))
    assert not on and text == OFF_TEXT and app.session.armed_state() == "off"  # fourth attempt: off, stop nagging


def test_standing_approval_env_and_admin_switch(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_LLM_MCP_ARM", "on")
    app = make_app(monkeypatch, tmp_path)
    on, text = gate(app, None)
    assert on and text == "" and app.session.meta["armed"]["source"] == "env"
    monkeypatch.setenv("LOCAL_LLM_MCP_ARM", "ask")
    app2 = make_app(monkeypatch, tmp_path / "b")
    # another process (the admin app) turns the session on by editing meta.json
    import json
    meta = json.loads(app2.session.meta_path.read_text())
    meta["armed"] = {"state": "on", "source": "admin"}
    app2.session.meta_path.write_text(json.dumps(meta))
    on, text = gate(app2, None)
    assert on and app2.session.meta["armed"]["source"] == "admin"


def test_bad_arm_value_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_LLM_MCP_ARM", "yes")
    import pytest
    from local_llm_mcp.config import ConfigError
    with pytest.raises(ConfigError):
        make_app(monkeypatch, tmp_path)


def test_dialog_text_names_tool_not_arguments():
    m = arm_message("assist", "worker-x", "local_llm_run")
    assert "local_llm_run" in m and "worker-x" in m and "ls" not in m
    assert EnableChoice.model_json_schema()["properties"]["choice"]["enum"] == ["off", "on", "on_pii"]  # off FIRST
    assert "choice" in EnableChoice.model_json_schema()["required"] and "default" not in EnableChoice.model_json_schema()["properties"]["choice"]


def test_auto_answered_dialogs_can_never_arm(monkeypatch, tmp_path):
    """A client that auto-accepts the form — empty, or with its first option — must not turn the server on."""
    app = make_app(monkeypatch, tmp_path)
    on, text = gate(app, FakeCtx(can_ask=True, action="accept", choice=""))       # accepted, nothing chosen
    assert not on and "did not answer" in text and app.session.armed_state() is None
    on, text = gate(app, FakeCtx(can_ask=True, action="accept", choice="yes"))    # accepted, not a listed choice
    assert not on and "did not answer" in text and app.session.armed_state() is None
    first = EnableChoice.model_json_schema()["properties"]["choice"]["enum"][0]
    on, text = gate(app, FakeCtx(can_ask=True, action="accept", choice=first))    # accepted with the FIRST option
    assert not on and text == OFF_TEXT and app.session.armed_state() == "off"
