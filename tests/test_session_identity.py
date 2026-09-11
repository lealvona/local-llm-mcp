"""Which conversation a server belongs to — and, above all, which one it does NOT.

Claude Code's hook writes a pidmap entry naming the conversation. Another agent harness can be
launched from inside a Claude Code session, and if it adopted that entry it would inherit the
conversation's vault, its memory and its answer to the opt-in gate. One client's approval must
never arm another.
"""
import local_llm_mcp.session as sess
from local_llm_mcp.config import Config
from local_llm_mcp.session import Session, write_pidmap


def make_cfg(monkeypatch, tmp_path) -> Config:
    for k in ("FALLBACK_BASE_URL", "API_KEY", "API_KEY_FILE", "RULES", "OBSERVER", "SESSION"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(tmp_path / "terms.json"))
    return Config.from_env()


def fake_tree(monkeypatch, chain):
    monkeypatch.setattr(sess, "ancestors", lambda start=None, max_depth=10: list(chain))


CLAUDE = (4100, "node", "/opt/bin/claude --resume")
SHELL = (4200, "bash", "/bin/bash -c local-llm-mcp")
CODEX = (4300, "codex", "/opt/bin/codex exec do the thing")
SELF = (4400, "python3", "/opt/venv/bin/local-llm-mcp")


def test_claude_code_session_is_adopted_from_the_pidmap(monkeypatch, tmp_path):
    cfg = make_cfg(monkeypatch, tmp_path)
    write_pidmap(cfg.state_dir, CLAUDE[0], "conv-abc")
    fake_tree(monkeypatch, [SELF, SHELL, CLAUDE])
    s = Session(cfg)
    assert s.under_claude and s.key == "conv-abc" and s.claude_session_id == "conv-abc"


def test_another_harness_under_claude_gets_its_own_session(monkeypatch, tmp_path):
    """The regression this file exists for: measured live on 2026-09-10, a Codex run launched
    from a Claude Code session adopted that session's id, vault, memory and arming state."""
    cfg = make_cfg(monkeypatch, tmp_path)
    write_pidmap(cfg.state_dir, CLAUDE[0], "conv-abc")
    fake_tree(monkeypatch, [SELF, SHELL, CODEX, SHELL, CLAUDE])
    s = Session(cfg)
    assert not s.under_claude
    assert s.key == f"pid-{CODEX[0]}" and s.claude_session_id == ""
    assert s.refresh_identity() is False  # and it does not drift onto it later either


def test_an_armed_claude_session_does_not_arm_the_other_harness(monkeypatch, tmp_path):
    cfg = make_cfg(monkeypatch, tmp_path)
    write_pidmap(cfg.state_dir, CLAUDE[0], "conv-abc")
    fake_tree(monkeypatch, [SELF, SHELL, CLAUDE])
    Session(cfg).set_armed("on", "dialog")
    fake_tree(monkeypatch, [SELF, SHELL, CODEX, SHELL, CLAUDE])
    assert Session(cfg).armed_state() is None  # the gate asks Codex's user for themselves


def test_an_explicit_session_override_still_wins(monkeypatch, tmp_path):
    cfg = make_cfg(monkeypatch, tmp_path)
    monkeypatch.setenv("LOCAL_LLM_MCP_SESSION", "named")
    cfg = Config.from_env()
    fake_tree(monkeypatch, [SELF, SHELL, CODEX, SHELL, CLAUDE])
    assert Session(cfg).key == "named"


def test_a_bare_shell_parent_falls_back_to_the_nearest_real_process(monkeypatch, tmp_path):
    cfg = make_cfg(monkeypatch, tmp_path)
    fake_tree(monkeypatch, [SELF, SHELL, SHELL, CODEX])
    s = Session(cfg)
    assert s.key == f"pid-{CODEX[0]}" and not s.under_claude
