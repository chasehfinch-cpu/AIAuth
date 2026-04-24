"""Canonical text normalization + hashing.

server.normalize_text() must behave identically to the extension's
chrome-extension/background.js normalizeText() so that the same logical
input produces the same hash regardless of where it was hashed. Any
change to either implementation that breaks this invariant silently
invalidates every previously issued receipt.

Rules under test (from CLAUDE.md "Content Hashing Rules"):
  1. Collapse any whitespace run to a single space.
  2. Trim leading / trailing whitespace.
  3. UTF-8 encode, then SHA-256, lowercase hex.
"""
from __future__ import annotations

import hashlib

import server


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_empty_and_none_are_empty_string():
    assert server.normalize_text("") == ""
    assert server.normalize_text(None) == ""


def test_collapse_spaces():
    assert server.normalize_text("hello   world") == "hello world"


def test_collapse_tabs_newlines_mixed():
    assert server.normalize_text("hello\t\tworld\n\nfoo") == "hello world foo"


def test_trim_leading_trailing():
    assert server.normalize_text("   hello   ") == "hello"


def test_utf8_preserved():
    # Non-ASCII characters must pass through unmodified.
    assert server.normalize_text("café — résumé") == "café — résumé"


def test_hash_normalized_lowercase_hex():
    h = server.hash_normalized("hello world")
    assert h == hashlib.sha256(b"hello world").hexdigest()
    assert h == h.lower()
    assert len(h) == 64


def test_format_independence_invariant():
    """The key invariant: text that differs only in whitespace layout
    must produce the same hash. Breaks if either normalize_text OR the
    extension's normalizeText ever drifts from the shared contract."""
    a = "The quick brown fox"
    b = "  The   quick\nbrown\t fox  "
    c = "The\tquick\n\nbrown   fox"
    assert server.hash_normalized(a) == server.hash_normalized(b)
    assert server.hash_normalized(a) == server.hash_normalized(c)


def test_whitespace_only_becomes_empty_hash():
    """Content that's only whitespace normalizes to empty string and so
    hashes to the well-known empty-string SHA-256."""
    empty_sha = hashlib.sha256(b"").hexdigest()
    assert server.hash_normalized("   \t\n   ") == empty_sha
    assert server.hash_normalized("") == empty_sha


def test_newline_inside_paragraph_is_single_space():
    """Markdown / editor line breaks inside a paragraph should not produce
    a different hash than the rendered prose. This is the scenario
    cross-format chain integrity relies on when text is re-flowed on
    export."""
    rendered = "A sentence that continues on the next line."
    markdown = "A sentence that continues\non the next line."
    assert server.hash_normalized(rendered) == server.hash_normalized(markdown)
