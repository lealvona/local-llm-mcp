"""Locate-then-quote: the worker finds WHERE, the server quotes EXACTLY.

A digest paraphrases, and a caller that needs code or config verbatim cannot use
it. In verbatim mode the worker is shown numbered lines and asked only for the
line ranges the task refers to; the server then copies those lines out of the
original material byte for byte (scrubbed on the way out like everything else).
The model's judgement picks the region; it never rewrites a character of it.
"""
from __future__ import annotations

import json
import re

_PAIR_RE = re.compile(r"\[?\s*(\d+)\s*(?:,|-|–|to)\s*(\d+)\s*\]?")


_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def parse_ranges(text: str, n_lines: int) -> list[tuple[int, int]]:
    """Accept a JSON array of [start, end] pairs (or dicts, or one flat pair), else loose
    'a-b' / 'a to b' / [a,b] pairs anywhere in the text; clip to the material and merge."""
    pairs: list[tuple[int, int]] = []
    body = _FENCE_RE.sub("", text.strip()).strip()
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, list):
        if len(data) == 2 and all(isinstance(x, int) for x in data):
            pairs.append((data[0], data[1]))                       # one flat pair: [start, end]
        else:
            for item in data:
                if isinstance(item, list) and len(item) == 2 and all(isinstance(x, int) for x in item):
                    pairs.append((item[0], item[1]))
                elif isinstance(item, dict) and "start" in item and "end" in item:
                    pairs.append((int(item["start"]), int(item["end"])))
                elif isinstance(item, int):
                    pairs.append((item, item))
    elif isinstance(data, dict) and "start" in data and "end" in data:
        pairs.append((int(data["start"]), int(data["end"])))
    if not pairs and data is None:
        for m in _PAIR_RE.finditer(text):
            pairs.append((int(m.group(1)), int(m.group(2))))
    return merge_ranges(pairs, n_lines)


def merge_ranges(pairs: list[tuple[int, int]], n_lines: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted((min(a, b), max(a, b)) for a, b in pairs):
        a, b = max(1, a), min(n_lines, b)
        if a > b:
            continue
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def number_lines(lines: list[str], first: int) -> str:
    """Render lines with absolute 1-based numbers, ``first`` being the number of lines[0]."""
    width = len(str(first + len(lines) - 1))
    return "\n".join(f"{first + i:>{width}}: {line}" for i, line in enumerate(lines))


def chunk_lines(lines: list[str], chunk_chars: int) -> list[tuple[int, int]]:
    """Split a line list into [start_idx, end_idx) index windows of about chunk_chars each."""
    windows: list[tuple[int, int]] = []
    start, size = 0, 0
    for i, line in enumerate(lines):
        size += len(line) + 1
        if size >= chunk_chars and i > start:
            windows.append((start, i + 1))
            start, size = i + 1, 0
    if start < len(lines):
        windows.append((start, len(lines)))
    return windows or [(0, 0)]


def quote(lines: list[str], ranges: list[tuple[int, int]], source: str, max_chars: int) -> tuple[str, list[tuple[int, int]]]:
    """Exact text for the ranges, numbered; stops at max_chars and returns what was left out."""
    parts: list[str] = []
    used = 0
    left: list[tuple[int, int]] = []
    for idx, (a, b) in enumerate(ranges):
        block = f"{source} lines {a}-{b}:\n" + number_lines(lines[a - 1:b], a)
        if used + len(block) > max_chars and parts:
            left = ranges[idx:]
            break
        parts.append(block)
        used += len(block) + 2
    return "\n\n".join(parts), left
