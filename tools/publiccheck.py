"""Refuse anything that belongs to ONE deployment or ONE person rather than to the code.

The general code must contain nothing about a particular network or operator: no private
network addresses, no home-directory paths, no non-example email addresses, no tailnet names,
and none of the terms in an operator's private denylist (a local file the repository never
sees). Deployment specifics belong in a separate instance — see the README's "Keeping a
deployment separate from the code".

The same checks run at every point where content could reach the repository:

    python tools/publiccheck.py                  # the tracked working tree (CI runs this)
    python tools/publiccheck.py --staged         # what a commit would record   (pre-commit hook)
    python tools/publiccheck.py --message FILE   # a commit message + the author/committer identity (commit-msg hook)
    python tools/publiccheck.py --range A..B     # every commit a push would publish: identity, message, trailers,
                                                 # file names and the FULL tree of each commit   (pre-push hook)
    python tools/publiccheck.py --all            # the entire history the same way

A tree line may opt out with ``public:allow`` (documentation that names an address range on
purpose, for example); messages and identities cannot. Denylist: one term per line in
``$LOCAL_LLM_MCP_DENYLIST`` (default ``~/.config/local-llm-mcp/publiccheck-denylist.txt``),
matched case-insensitively on word boundaries and reported by line number, never by value.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

CHECKS = [
    ("private IPv4 address", re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
        r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b(?!/\d)")),
    ("home directory path", re.compile(r"(?<![A-Za-z0-9_])/home/[a-z][a-z0-9_-]*/")),
    ("non-example email address", re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:org|com|net)\b|users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("tailnet hostname", re.compile(r"\b[a-z0-9-]+\.[a-z0-9]+\.ts\.net\b")),
]
ATTRIBUTION = re.compile(r"^\s*(?:co-authored-by\s*:|generated with\b|🤖)", re.I | re.M)
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock")
NULL_SHA = "0" * 40


def git(*args: str, text: bool = True, check: bool = True) -> str | bytes:
    out = subprocess.run(["git", *args], check=check, capture_output=True)
    return out.stdout.decode("utf-8", "replace") if text else out.stdout


def root() -> Path:
    try:
        return Path(git("rev-parse", "--show-toplevel").strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(__file__).resolve().parent.parent


def denylist() -> list[tuple[int, re.Pattern[str]]]:
    p = os.environ.get("LOCAL_LLM_MCP_DENYLIST")
    path = Path(p) if p else Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "local-llm-mcp" / "publiccheck-denylist.txt"
    if not path.is_file():
        return []
    terms = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        t = line.strip()
        if t and not t.startswith("#"):
            terms.append((n, re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I)))
    return terms


class Scanner:
    def __init__(self) -> None:
        self.hits: list[str] = []
        self.deny = denylist()
        self.seen_blobs: set[str] = set()

    def text(self, text: str, where: str, optout: bool = True) -> None:
        for lineno, line in enumerate(text.splitlines(), 1):
            if optout and "public:allow" in line:
                continue
            loc = f"{where}:{lineno}" if "\n" in text or lineno > 1 else where
            for label, pat in CHECKS:
                m = pat.search(line)
                if m and not (label == "private IPv4 address" and m.group(0).endswith(".0.0")):
                    self.hits.append(f"{loc}: {label}: {m.group(0)}")
            for n, pat in self.deny:
                if pat.search(line):
                    self.hits.append(f"{loc}: denylist term #{n}")

    def file(self, name: str, data: bytes, where: str) -> None:
        # a denylisted term in a file NAME must not be echoed back through any location string
        if any(pat.search(name) for _, pat in self.deny):
            where = where.replace(name, "<file name>")
        self.text(name, f"{where} (file name)", optout=False)
        if name.lower().endswith(SKIP_SUFFIXES):
            return
        try:
            self.text(data.decode("utf-8"), where)
        except UnicodeDecodeError:
            return

    def blob(self, oid: str, name: str, where: str) -> None:
        if oid in self.seen_blobs:  # the same content under the same name was scanned in an earlier commit
            return
        self.seen_blobs.add(oid)
        self.file(name, git("cat-file", "blob", oid, text=False), where)

    def message(self, msg: str, where: str) -> None:
        self.text(msg, where, optout=False)
        if ATTRIBUTION.search(msg):
            self.hits.append(f"{where}: attribution trailer (Co-Authored-By / generated-with) is not accepted")

    def identity(self, name: str, email: str, role: str, where: str) -> None:
        exp_name, exp_email = expected_identity()
        if not exp_email:
            self.hits.append(f"{where}: no user.email configured for this repository; refusing to guess an identity")
        elif (name, email) != (exp_name, exp_email):
            self.hits.append(f"{where}: {role} is {name} <{email}>, not the configured {exp_name} <{exp_email}>")


def expected_identity() -> tuple[str, str]:
    """The standing identity from the config FILES (this repository's, else the user's) — so that a
    one-off `git -c user.email=...` override is compared against it rather than against itself."""
    name = (git("config", "--local", "--get", "user.name", check=False).strip()
            or git("config", "--global", "--get", "user.name", check=False).strip())
    email = (git("config", "--local", "--get", "user.email", check=False).strip()
             or git("config", "--global", "--get", "user.email", check=False).strip())
    return name, email


def scan_tree(s: Scanner) -> None:
    top = root()
    try:
        names = [n for n in git("ls-files", "-z").split("\0") if n]
    except (subprocess.CalledProcessError, FileNotFoundError):
        names = [str(p.relative_to(top)) for p in top.rglob("*") if p.is_file() and ".git" not in p.parts]
    for n in names:
        p = top / n
        if p.is_file():
            s.file(n, p.read_bytes(), n)


def scan_staged(s: Scanner) -> None:
    out = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    for n in (x for x in out.split("\0") if x):
        s.file(n, git("show", f":{n}", text=False), f"staged {n}")


def scan_message(s: Scanner, path: str) -> None:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    msg = "\n".join(l for l in raw.splitlines() if not l.startswith("#"))  # git's commented template lines
    s.message(msg, "commit message")
    for var, role in (("GIT_AUTHOR_IDENT", "author"), ("GIT_COMMITTER_IDENT", "committer")):
        ident = git("var", var).strip()
        m = re.match(r"^(.*?) <([^>]*)> \d+ [+-]\d{4}$", ident)
        if m:
            s.identity(m.group(1), m.group(2), role, "commit")
        else:
            s.hits.append(f"commit: cannot parse {var}: {ident!r}")


def commits(spec: str | None, everything: bool) -> list[str]:
    if everything:
        args = ["rev-list", "--all"]
    elif spec and ".." in spec:
        args = ["rev-list", spec]
    else:
        args = ["rev-list", spec or "HEAD", "--not", "--remotes"]  # reachable and not yet on any remote
    return [c for c in git(*args).split() if c]


def scan_commits(s: Scanner, revs: list[str]) -> None:
    # A history scan on a machine with no configured identity (CI, a fresh clone) checks everything
    # else and says so; the commit-msg and pre-push hooks run where the identity IS configured.
    check_identity = bool(expected_identity()[1])
    if not check_identity:
        print("publiccheck: no user.email configured here — identities not checked in this history scan")
    for c in reversed(revs):
        short = c[:7]
        an, ae, cn, ce, body = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", c).split("\0", 4)
        if check_identity:
            s.identity(an, ae, "author", f"commit {short}")
            s.identity(cn, ce, "committer", f"commit {short}")
        s.message(body, f"commit {short} message")
        for line in git("ls-tree", "-r", "-z", c).split("\0"):
            if not line:
                continue
            meta, name = line.split("\t", 1)
            oid = meta.split()[2]
            s.blob(oid, name, f"commit {short}:{name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true", help="scan the index (what a commit would record)")
    g.add_argument("--message", metavar="FILE", help="scan a commit message and the author/committer identity")
    g.add_argument("--range", metavar="SPEC", help="scan every commit in SPEC (A..B, or a tip: everything not yet on a remote)")
    g.add_argument("--all", action="store_true", help="scan every commit in the repository")
    a = ap.parse_args()
    s = Scanner()
    if a.staged:
        scan_staged(s); what = "staged changes"
    elif a.message:
        scan_message(s, a.message); what = "commit message and identity"
    elif a.range or a.all:
        revs = commits(a.range, a.all)
        scan_commits(s, revs); what = f"{len(revs)} commit(s)"
    else:
        scan_tree(s); what = "tracked tree"
    if s.hits:
        print(f"publiccheck: REFUSED — deployment-specific or personal content in the {what}:", file=sys.stderr)
        for h in s.hits:
            print("  " + h, file=sys.stderr)
        print("  (a tree line may carry 'public:allow' when it names an address range on purpose; "
              "messages, file names and identities cannot opt out)", file=sys.stderr)
        return 1
    print(f"publiccheck: clean ({what}" + (f", denylist of {len(s.deny)} terms" if s.deny else ", no denylist") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
