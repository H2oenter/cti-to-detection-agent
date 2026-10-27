"""Refanging, text normalisation, quote matching and hashing.

The evidence check (design rule 4) compares a model's quote with the source
text. PDF extraction and report authors both mangle text in predictable ways, so
both sides go through the same normalisation before comparing:

* Unicode NFKC (folds ligatures such as "fi" and non-breaking spaces)
* curly quotes and dashes folded to ASCII, soft hyphens and zero-width chars dropped
* defanged notation refanged (hxxp, [.], [:], [@], ...)
* whitespace collapsed

Line-break hyphenation is ambiguous ("follow-\\nup" vs "Power-\\nShell"), so the
source is indexed in three variants and a quote matches if it is in any of them.
Nothing is paraphrase-tolerant: the words have to be the same words.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bhxxp(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bfxp\b", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\s*:\s*\]\s*//"), "://"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]|\(\s*at\s*\)", re.IGNORECASE), "@"),
]

_FOLD = {
    **{ord(c): "'" for c in "‘’‚‛′"},
    **{ord(c): '"' for c in "“”„‟″"},
    **{ord(c): "-" for c in "‐‑‒–—―−"},
    **{ord(c): None for c in "­​‌‍⁠﻿"},
}

_WS = re.compile(r"\s+")
_PARAGRAPH = re.compile(r"\n\s*\n")
_LINEBREAK_HYPHEN = re.compile(r"(\w)-[ \t]*\r?\n\s*(\w)")


def refang(text: str) -> str:
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def fold(text: str) -> str:
    """Unicode and typography normalisation, without touching whitespace."""
    return unicodedata.normalize("NFKC", text).translate(_FOLD)


def collapse_ws(text: str) -> str:
    return _WS.sub(" ", text).strip()


def match_key(text: str) -> str:
    """The form a quote is compared in."""
    return collapse_ws(refang(fold(text)))


def _variants(text: str) -> tuple[str, ...]:
    folded = fold(text)
    kept = _LINEBREAK_HYPHEN.sub(r"\1-\2", folded)  # "follow-\nup" -> "follow-up"
    dropped = _LINEBREAK_HYPHEN.sub(r"\1\2", folded)  # "Power-\nShell" -> "PowerShell"
    return tuple(dict.fromkeys(collapse_ws(refang(v)) for v in (folded, kept, dropped)))


@dataclass
class QuoteMatch:
    found: bool
    page: int | None = None  # 1-based; None if the quote spans pages or the doc has no pages


@dataclass
class SourceIndex:
    """Normalised views of a source document, for evidence lookups."""

    pages: list[str]
    _page_keys: list[tuple[str, ...]] = field(init=False, repr=False)
    _doc_keys: tuple[str, ...] = field(init=False, repr=False)
    _para_keys: list[tuple[str, ...]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._page_keys = [_variants(p) for p in self.pages]
        self._doc_keys = _variants("\n".join(self.pages))
        self._para_keys = [
            _variants(para)
            for page in self.pages
            for para in _PARAGRAPH.split(page)
            if para.strip()
        ]

    def find(self, quote: str) -> QuoteMatch:
        key = match_key(quote)
        if not key:
            return QuoteMatch(found=False)
        paged = len(self.pages) > 1
        for number, variants in enumerate(self._page_keys, start=1):
            if any(key in v for v in variants):
                return QuoteMatch(found=True, page=number if paged else None)
        if any(key in v for v in self._doc_keys):
            return QuoteMatch(found=True, page=None)
        return QuoteMatch(found=False)

    def contains(self, text: str) -> bool:
        return self.find(text).found

    def surrounding(self, quote: str, radius: int = 300) -> str | None:
        """The source text around a quote, trimmed to whole words, for readers of the evidence."""
        window = self.context(quote, radius)
        if window is None:
            return None
        key = match_key(quote)
        start, end = window.find(key), window.find(key) + len(key)
        head, tail = window[:start], window[end:]
        head = head[head.find(" ") + 1 :] if " " in head and len(head) >= radius else head
        tail = tail[: tail.rfind(" ")] if " " in tail and len(tail) >= radius else tail
        return f"{head}{key}{tail}".strip()

    def context(self, quote: str, radius: int = 200) -> str | None:
        """The normalised source text around a quote, for checks that need surroundings."""
        key = match_key(quote)
        if not key:
            return None
        for variant in self._doc_keys:
            start = variant.find(key)
            if start >= 0:
                return variant[max(0, start - radius) : start + len(key) + radius]
        return None

    def paragraph_context(self, quote: str, radius: int = 200) -> str | None:
        """Like context(), but never crossing out of the paragraph the quote is in, so text
        planted in a neighbouring paragraph doesn't taint it. Falls back to context() when
        the quote spans paragraphs."""
        key = match_key(quote)
        if not key:
            return None
        for variants in self._para_keys:
            for variant in variants:
                start = variant.find(key)
                if start >= 0:
                    return variant[max(0, start - radius) : start + len(key) + radius]
        return self.context(quote, radius)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def item_hash(obj: Any) -> str:
    """Stable hash of an item's content, used in the audit log."""
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump(mode="json")
    return "sha256:" + sha256_bytes(canonical_json(obj).encode("utf-8"))
