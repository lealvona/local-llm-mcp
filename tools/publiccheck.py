"""Refuse anything that belongs to ONE deployment or ONE person rather than to the code.

The general code must contain nothing about a particular network or operator: no network addresses,
no home-directory paths, no non-example email addresses, no tailnet names, and none of the terms in
an operator's private denylist (a local file the repository never sees). Deployment specifics belong
in a separate instance — see the README's "Keeping a deployment separate from the code".

The same checks run at every point where content could reach the repository:

    python tools/publiccheck.py                  # the tracked working tree (CI runs this)
    python tools/publiccheck.py --staged         # what a commit would record   (pre-commit hook)
    python tools/publiccheck.py --message FILE   # a commit message + the author/committer identity (commit-msg hook)
    python tools/publiccheck.py --range A..B     # every commit a push would publish: identity, message, trailers,
                                                 # file names and the FULL tree of each commit   (pre-push hook)
    python tools/publiccheck.py --tag REF        # an annotated tag's message and tagger          (pre-push hook)
    python tools/publiccheck.py --all            # the entire history the same way, tags included

A tree line may opt out with ``public:allow <check name>`` — naming the check it exempts, e.g. ``public:allow private IPv4
address`` on a line that quotes an address on purpose; a bare ``public:allow`` exempts the shape
checks on that line. **A denylist term can never be opted out**, and neither can a commit message, a
file name or an identity. Range constants defined by RFC (``100.64.0.0/10`` and friends) need no
opt-out at all; a real subnet still does.

Denylist: one term per line in ``$LOCAL_LLM_MCP_DENYLIST`` (default
``~/.config/local-llm-mcp/publiccheck-denylist.txt``), matched case-insensitively on word boundaries
and reported by line number, never by value.

Matched values are printed only when stderr is a terminal, or with ``--show-values``. Everywhere else
— CI logs above all, which are world-readable on a public repository — a refusal names the check and
the location and withholds the value, so the gate can never publish what it caught.
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
        r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b")),
    ("public IPv4 address", re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")),
    ("IPv6 address", re.compile(r"(?<![\w:])(?:fd[0-9a-f]{2}:[0-9a-f:]{2,}|fe80:[0-9a-f:]{2,})(?![\w:])", re.I)),
    ("home directory path", re.compile(r"(?<![A-Za-z0-9_])(?:/home/[A-Za-z][\w.-]*|/Users/[A-Za-z][\w.-]*|/root(?![\w.-])"  # public:allow home directory path
                                       r"|[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z][\w.-]*)")),  # public:allow home directory path
    ("non-example email address", re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:org|com|net)\b|users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("tailnet hostname", re.compile(r"\b[a-z0-9-]+\.[a-z0-9]+\.ts\.net\b")),
]
# Range constants defined by RFC, not anyone's network — allowed by value so documentation and code
# may name them, while a real subnet (192.168.1.0/24) is still refused.  public:allow private IPv4 address
RFC_RANGES = {"0.0.0.0", "10.0.0.0", "127.0.0.0", "169.254.0.0", "172.16.0.0", "192.168.0.0",
              "100.64.0.0", "224.0.0.0", "255.255.255.255"}
ATTRIBUTION = re.compile(r"^\s*(?:co-authored-by\s*:|generated with\b|🤖)", re.I | re.M)
# Binary formats only. Everything text — lockfiles included — is scanned; a lockfile is exactly where a
# private index URL or a file:///home/<user>/ source lands without anyone reading the diff.
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".woff", ".woff2", ".ttf", ".zip", ".gz")
NULL_SHA = "0" * 40
SHOW_VALUES = sys.stderr.isatty() or "--show-values" in sys.argv


def hidden(value: str) -> str:
    """A refusal must never publish what it caught. Terminals get the value; CI logs get its size."""
    return value if SHOW_VALUES else f"<withheld, {len(value)} chars — rerun in a terminal or with --show-values>"


def public_ipv4(text: str) -> bool:
    """True for a routable public address. Private ranges have their own check; loopback, link-local,
    multicast, reserved, and the RFC 5737 documentation ranges are not anybody's machine."""
    try:
        o = [int(x) for x in text.split(".")]
    except ValueError:
        return False
    if len(o) != 4 or any(n > 255 for n in o):
        return False
    a, b, c = o[0], o[1], o[2]
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a == 169 and b == 254:
        return False
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
        return False
    if a == 198 and b in (18, 19):
        return False
    return True


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
            terms.append((n, re.compile(r"(?<![A-Za-z0-9])" + re.escape(t).replace(r"\ ", r"[\s_-]+") + r"(?![A-Za-z0-9])", re.I)))
    return terms


class Scanner:
    def __init__(self) -> None:
        self.hits: list[str] = []
        self.deny = denylist()
        self.seen_blobs: set[str] = set()

    def text(self, text: str, where: str, optout: bool = True) -> None:
        for lineno, line in enumerate(text.splitlines(), 1):
            loc = f"{where}:{lineno}" if "\n" in text or lineno > 1 else where
            has_allow = bool(re.search(r"public:allow", line)) if optout else False
            allow_text = " ".join(re.findall(r"public:allow[: ]+([^\n]*)", line)).lower() if has_allow else ""
            named = [lbl for lbl, _ in CHECKS if lbl.lower() in allow_text]
            for label, pat in CHECKS:
                m = pat.search(line)
                if not m:
                    continue
                if label == "public IPv4 address" and not public_ipv4(m.group(1)):
                    continue
                if label == "private IPv4 address" and m.group(0) in RFC_RANGES:
                    continue
                # An opt-out that NAMES checks exempts only those; a bare one exempts the shape checks.
                # Neither ever exempts a denylist term — that is the whole point of the list.
                if has_allow and (not named or label in named):
                    continue
                self.hits.append(f"{loc}: {label}: {hidden(m.group(0))}")
            for n, pat in self.deny:  # a denylist term can never be opted out
                if pat.search(line):
                    self.hits.append(f"{loc}: denylist term #{n}")

    def file(self, name: str, data: bytes, where: str) -> None:
        if any(pat.search(name) for _, pat in self.deny):
            where = where.replace(name, "<file name>")  # never echo a denylisted term through a location
        self.text(name, f"{where} (file name)", optout=False)
        if name.lower().endswith(SKIP_SUFFIXES):
            return
        try:
            self.text(data.decode("utf-8"), where)
        except UnicodeDecodeError:
            return

    def blob(self, oid: str, name: str, where: str) -> None:
        if oid in self.seen_blobs:
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
            self.hits.append(f"{where}: {role} is {hidden(name + ' <' + email + '>')}, not the configured {exp_name} <{exp_email}>")


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
    msg = "\n".join(l for l in raw.splitlines() if not l.startswith("#"))
    s.message(msg, "commit message")
    for var, role in (("GIT_AUTHOR_IDENT", "author"), ("GIT_COMMITTER_IDENT", "committer")):
        ident = git("var", var).strip()
        m = re.match(r"^(.*?) <([^>]*)> \d+ [+-]\d{4}$", ident)
        if m:
            s.identity(m.group(1), m.group(2), role, "commit")
        else:
            s.hits.append(f"commit: cannot parse {var}")


def scan_tag(s: Scanner, ref: str) -> None:
    """An annotated tag carries its own message and tagger, and `git rev-list` never shows either."""
    kind = git("cat-file", "-t", ref, check=False).strip()
    if kind != "tag":
        return
    body = git("cat-file", "-p", ref)
    header, _, msg = body.partition("\n\n")
    s.message(msg, f"tag {ref} message")
    m = re.search(r"^tagger (.*?) <([^>]*)> \d+ [+-]\d{4}$", header, re.M)
    if m:
        s.identity(m.group(1), m.group(2), "tagger", f"tag {ref}")


def annotated_tags() -> list[str]:
    out = git("for-each-ref", "--format=%(objecttype) %(objectname)", "refs/tags", check=False)
    return [line.split()[1] for line in out.splitlines() if line.startswith("tag ")]


def commits(spec: str | None, everything: bool) -> list[str]:
    if everything:
        args = ["rev-list", "--all"]
    elif spec and ".." in spec:
        args = ["rev-list", spec]
    else:
        args = ["rev-list", spec or "HEAD", "--not", "--remotes"]
    return [c for c in git(*args).split() if c]


def scan_commits(s: Scanner, revs: list[str]) -> None:
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
            s.blob(meta.split()[2], name, f"commit {short}:{name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true", help="scan the index (what a commit would record)")
    g.add_argument("--message", metavar="FILE", help="scan a commit message and the author/committer identity")
    g.add_argument("--range", metavar="SPEC", help="scan every commit in SPEC (A..B, or a tip: everything not yet on a remote)")
    g.add_argument("--tag", metavar="REF", help="scan an annotated tag's message and tagger")
    g.add_argument("--all", action="store_true", help="scan every commit and every annotated tag in the repository")
    ap.add_argument("--show-values", action="store_true", help="print matched values even when stderr is not a terminal")
    a = ap.parse_args()
    s = Scanner()
    if a.staged:
        scan_staged(s); what = "staged changes"
    elif a.message:
        scan_message(s, a.message); what = "commit message and identity"
    elif a.tag:
        scan_tag(s, a.tag); what = f"tag {a.tag}"
    elif a.range or a.all:
        revs = commits(a.range, a.all)
        scan_commits(s, revs)
        tags = annotated_tags() if a.all else []
        for t in tags:
            scan_tag(s, t)
        what = f"{len(revs)} commit(s)" + (f" and {len(tags)} annotated tag(s)" if tags else "")
    else:
        scan_tree(s); what = "tracked tree"
    if s.hits:
        print(f"publiccheck: REFUSED — deployment-specific or personal content in the {what}:", file=sys.stderr)
        for h in s.hits:
            print("  " + h, file=sys.stderr)
        print("  (a tree line may opt out with 'public:allow <check name>' when it quotes an address range on "
              "purpose; denylist terms, messages, file names and identities can never opt out)", file=sys.stderr)
        return 1
    if s.deny:
        print(f"publiccheck: clean ({what}, denylist of {len(s.deny)} terms)")
    else:
        # Silence here would read as an all-clear. The regexes catch shapes; only the denylist catches NAMES —
        # host names, model aliases, real domains — so say plainly that half the gate did not run.
        print(f"publiccheck: {what} pass the {len(CHECKS)} shape checks, but NO DENYLIST was found "
              f"(${'LOCAL_LLM_MCP_DENYLIST'} unset / file absent): name-based checks did NOT run here. "
              f"This is expected on CI; the pre-commit, commit-msg and pre-push hooks enforce the denylist "
              f"on the machine that authors the commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
