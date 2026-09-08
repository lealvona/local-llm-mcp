"""Locate-then-quote helpers: range parsing, merging, chunking, exact quoting."""
from local_llm_mcp.verbatim import chunk_lines, merge_ranges, number_lines, parse_ranges, quote


def test_parse_json_pairs_and_dicts_and_ints():
    assert parse_ranges('[[3, 5], {"start": 10, "end": 12}, 20]', 100) == [(3, 5), (10, 12), (20, 20)]


def test_parse_loose_pairs_when_not_json():
    assert parse_ranges("lines 4-6 and 9 to 11, also [40,41]", 100) == [(4, 6), (9, 11), (40, 41)]


def test_parse_clips_merges_and_orders():
    assert parse_ranges("[[8, 3], [4, 6], [0, 1], [95, 200]]", 100) == [(1, 1), (3, 8), (95, 100)]
    assert merge_ranges([(1, 2), (3, 4)], 10) == [(1, 4)]  # adjacent ranges fuse


def test_parse_flat_pair_and_fenced_json():
    assert parse_ranges("[127, 132]", 500) == [(127, 132)]          # one flat pair is one range
    assert parse_ranges("```json\n[[3, 5]]\n```", 10) == [(3, 5)]
    assert parse_ranges("Here you go: [[3, 5]]", 10) == [(3, 5)]    # prose around it: loose pass


def test_parse_empty_or_garbage():
    assert parse_ranges("[]", 10) == []
    assert parse_ranges("nothing here", 10) == []


def test_number_lines_is_aligned_and_absolute():
    out = number_lines(["a", "b"], 99)
    assert out == " 99: a\n100: b"


def test_chunk_lines_covers_everything_in_order():
    lines = [f"line {i}" for i in range(50)]
    windows = chunk_lines(lines, 60)
    assert windows[0][0] == 0 and windows[-1][1] == 50
    assert all(windows[i][1] == windows[i + 1][0] for i in range(len(windows) - 1))


def test_quote_is_exact_and_budgeted():
    lines = [f"L{i}" for i in range(1, 21)]
    text, left = quote(lines, [(2, 3), (10, 12)], "file.py", max_chars=10_000)
    assert "file.py lines 2-3:" in text and "2: L2\n3: L3" in text and "10: L10" in text and left == []
    text, left = quote(lines, [(1, 5), (10, 12)], "f", max_chars=40)
    assert "1: L1" in text and left == [(10, 12)]  # second range did not fit and is reported
