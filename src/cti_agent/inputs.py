"""Load a local report file into text, keeping page boundaries for evidence lookups.

Local files only: nothing here follows links or fetches anything (design rule 3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from bs4 import BeautifulSoup
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from cti_agent.util.normalise import sha256_file

MAX_BYTES = 50 * 1024 * 1024
TEXT_SUFFIXES = {".txt", ".md", ".text"}
HTML_SUFFIXES = {".html", ".htm"}


class InputError(Exception):
    pass


@dataclass(frozen=True)
class SourceDoc:
    path: Path
    sha256: str
    media_type: Literal["pdf", "html", "text"]
    pages: list[str]

    @property
    def text(self) -> str:
        return "\n\n".join(self.pages)


def load_source(path: Path) -> SourceDoc:
    if not path.is_file():
        raise InputError(f"not a file: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise InputError(f"{path.name} is larger than {MAX_BYTES // (1024 * 1024)} MB")
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        media_type, pages = "pdf", _read_pdf(path)
    elif suffix in HTML_SUFFIXES:
        media_type, pages = "html", [_read_html(path)]
    elif suffix in TEXT_SUFFIXES:
        media_type, pages = "text", [path.read_text(encoding="utf-8", errors="replace")]
    else:
        raise InputError(f"unsupported file type {suffix!r}: use PDF, HTML or text")
    if not any(page.strip() for page in pages):
        raise InputError(f"no extractable text in {path.name} (is it a scanned PDF?)")
    return SourceDoc(path=path, sha256=sha256_file(path), media_type=media_type, pages=pages)


def _read_pdf(path: Path) -> list[str]:
    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted and not reader.decrypt(""):
            raise InputError(f"{path.name} is password-protected")
        return [page.extract_text() or "" for page in reader.pages]
    except PdfReadError as exc:
        raise InputError(f"could not read {path.name}: {exc}") from exc


def _read_html(path: Path) -> str:
    soup = BeautifulSoup(path.read_bytes(), "html.parser")
    for tag in soup(["script", "style", "noscript", "template", "svg"]):
        tag.decompose()
    lines = (line.strip() for line in soup.get_text("\n").splitlines())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
