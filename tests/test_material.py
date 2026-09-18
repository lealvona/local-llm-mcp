"""run_command resolves bash from PATH rather than a hardcoded location, and fails
cleanly — not with an opaque asyncio FileNotFoundError — when there is none."""
import asyncio

import pytest

from local_llm_mcp.material import ShellNotFound, run_command


def run(**kw):
    return asyncio.run(run_command(cwd=None, timeout=5, max_chars=2000, **kw))


def test_a_command_actually_runs():
    res = run(cmd="echo hello")
    assert res.rc == 0 and "hello" in res.output


def test_no_bash_on_path_is_a_clean_refusal_not_a_crash(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir: nothing resolves
    with pytest.raises(ShellNotFound, match="local_llm_run"):
        run(cmd="echo hello")


def test_bash_need_not_live_at_bin_bash(monkeypatch, tmp_path):
    """The fix this guards: a system whose bash is anywhere else on PATH still works —
    the old code hardcoded executable="/bin/bash" and would have crashed here."""
    real_bash = __import__("shutil").which("bash")
    if not real_bash:
        pytest.skip("no bash installed to relocate for this test")
    fake_dir = tmp_path / "bin"
    fake_dir.mkdir()
    (fake_dir / "bash").symlink_to(real_bash)
    monkeypatch.setenv("PATH", str(fake_dir))
    res = run(cmd="echo hello")
    assert res.rc == 0 and "hello" in res.output
