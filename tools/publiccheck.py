"""Fail if the tracked tree carries anything that belongs to ONE deployment rather than to the code.

The general code must contain nothing about a particular network or operator: no private
network addresses, no home-directory paths, no non-example email addresses. Deployment
specifics belong in a separate instance (dotenv, keys, terms, plugins) — see the README's
"Keeping a deployment separate from the code". A line may opt out with ``public:allow``
(documentation that names an address range on purpose, for example).

    python tools/publiccheck.py            # exit 1 with a listing when something is found
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKS = [
    ("private IPv4 address", re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
        r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b(?!/\d)")),
    ("home directory path", re.compile(r"(?<![A-Za-z0-9_])/home/[a-z][a-z0-9_-]*/")),
    ("non-example email address", re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:org|com|net)\b|users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("tailnet hostname", re.compile(r"\b[a-z0-9-]+\.[a-z0-9]+\.ts\.net\b")),
]
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock")


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
        names = [n for n in out.decode("utf-8", "replace").split("\0") if n]
    except (subprocess.CalledProcessError, FileNotFoundError):
        names = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    return [ROOT / n for n in names]


def main() -> int:
    hits: list[str] = []
    for path in tracked_files():
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if "public:allow" in line:
                continue
            for label, pat in CHECKS:
                m = pat.search(line)
                if m and not (label == "private IPv4 address" and m.group(0).endswith(".0.0")):
                    hits.append(f"{path.relative_to(ROOT)}:{lineno}: {label}: {m.group(0)}")
    if hits:
        print("publiccheck: deployment-specific content in the tree:", file=sys.stderr)
        for h in hits:
            print("  " + h, file=sys.stderr)
        return 1
    print("publiccheck: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
