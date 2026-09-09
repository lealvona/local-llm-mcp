"""The git gate: nothing deployment-specific or personal reaches a commit, a message, or a push."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "tools" / "githooks"
CHECK = ROOT / "tools" / "publiccheck.py"


@pytest.fixture
def repo(tmp_path):
    """A throwaway repository wired to the tracked hooks, a bare remote, and a private denylist."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
           "LOCAL_LLM_MCP_DENYLIST": str(tmp_path / "deny.txt"), "GIT_TERMINAL_PROMPT": "0"}
    (tmp_path / "deny.txt").write_text("# private terms\norchid-nine\nhost-zebra\n")
    work, bare = tmp_path / "work", tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, env=env)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True, env=env)

    def g(*args, check=True, **kw):
        return subprocess.run(["git", *args], cwd=work, env=env, capture_output=True, text=True, check=check, **kw)

    g("config", "user.name", "Test Author")
    g("config", "user.email", "author@example.org")
    g("config", "core.hooksPath", str(HOOKS))
    g("remote", "add", "origin", str(bare))
    (work / "README.md").write_text("hello\n")
    g("add", "README.md")
    g("commit", "-q", "-m", "first")
    g("push", "-q", "-u", "origin", "main")
    return work, g


def test_clean_commit_and_push_pass(repo):
    work, g = repo
    (work / "a.py").write_text("print('fine')\n")
    g("add", "a.py")
    assert g("commit", "-q", "-m", "add a").returncode == 0
    assert g("push", "-q").returncode == 0


def test_staged_private_address_is_refused(repo):
    work, g = repo
    (work / "cfg.py").write_text("URL = 'http://192.168.4.20:8000'\n")  # public:allow: synthetic fixture
    g("add", "cfg.py")
    r = g("commit", "-q", "-m", "wire it", check=False)
    assert r.returncode != 0 and "private IPv4 address" in r.stderr and "staged cfg.py" in r.stderr
    assert "wire it" not in g("log", "--oneline").stdout


def test_staged_denylisted_term_and_file_name_are_refused(repo):
    work, g = repo
    (work / "notes-host-zebra.md").write_text("Orchid-Nine handles the rest.\n")  # case-insensitive, word-bounded
    g("add", "notes-host-zebra.md")
    r = g("commit", "-q", "-m", "notes", check=False)
    assert r.returncode != 0 and "denylist term #2" in r.stderr and "denylist term #3" in r.stderr
    assert "orchid" not in r.stderr.lower() and "zebra" not in r.stderr.lower()  # reported by number, never by value


def test_message_with_term_address_or_attribution_is_refused(repo):
    work, g = repo
    (work / "b.py").write_text("x = 1\n")
    g("add", "b.py")
    for msg, expect in [("tested on host-zebra", "denylist term #3"),
                        ("see /home/someone/notes", "home directory path"),  # public:allow: synthetic fixture
                        ("add b\n\nCo-Authored-By: Robot <robot@example.org>", "attribution trailer"),
                        ("add b\n\n🤖 Generated with Something", "attribution trailer")]:
        r = g("commit", "-q", "-m", msg, check=False)
        assert r.returncode != 0 and expect in r.stderr, msg
    assert g("commit", "-q", "-m", "add b").returncode == 0


def test_wrong_identity_is_refused(repo):
    work, g = repo
    (work / "c.py").write_text("y = 2\n")
    g("add", "c.py")
    r = g("commit", "-q", "-m", "add c", "--author=Someone Else <else@example.org>", check=False)
    assert r.returncode != 0 and "author is Someone Else <else@example.org>, not the configured Test Author" in r.stderr
    r = g("-c", "user.email=other@example.org", "commit", "-q", "-m", "add c", check=False)
    assert r.returncode != 0 and ("committer is" in r.stderr or "author is" in r.stderr)


def test_push_refuses_a_commit_that_bypassed_the_earlier_hooks(repo):
    work, g = repo
    (work / "d.py").write_text("HOST = '10.1.2.3'\n")  # public:allow: synthetic fixture
    g("add", "d.py")
    assert g("commit", "-q", "--no-verify", "-m", "sneaky").returncode == 0  # skips pre-commit and commit-msg
    (work / "e.py").write_text("ok = True\n")
    g("add", "e.py")
    g("commit", "-q", "--no-verify", "-m", "on top\n\nCo-Authored-By: Robot <robot@example.org>")
    r = g("push", "-q", check=False)
    assert r.returncode != 0 and "private IPv4 address" in r.stderr and "attribution trailer" in r.stderr
    assert "2 commit(s)" in r.stderr
    g("reset", "-q", "--hard", "HEAD~2")
    assert g("push", "-q").returncode == 0


def test_range_and_all_scan_every_commit_tree_not_only_diffs(repo):
    work, g = repo
    (work / "f.py").write_text("addr = '172.16.9.9'\n")  # public:allow: synthetic fixture
    g("add", "f.py")
    g("commit", "-q", "--no-verify", "-m", "bad")
    (work / "f.py").write_text("addr = 'gone'\n")
    g("add", "f.py")
    g("commit", "-q", "-m", "fixed")  # the tip is clean; the history is not
    env = {**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt")}
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "private IPv4 address" in r.stderr
    r = subprocess.run([sys.executable, str(CHECK)], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 0  # the tree alone is clean — which is exactly why the push gate scans commits


def test_this_repository_history_is_clean():
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
