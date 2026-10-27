"""The only network code in the pipeline outside the model client. GET only, allowlisted hosts.

Design rule 3: URLs come from fixed templates in data/sources.toml plus an ID that must
match the source's pattern. A redirect to a host that isn't allowlisted is refused, and
every URL requested is logged so a run can show where it went.
"""

from __future__ import annotations

import re
import tomllib
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

USER_AGENT = "cti-to-detection-agent/0.1 (+https://github.com/H2oenter/cti-to-detection-agent)"


class FeedError(Exception):
    pass


def load_sources(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def build_url(template: str, id_pattern: str | None = None, **fields: str) -> str:
    """Fill a template. Every ID goes through the source's pattern first."""
    if id_pattern and "id" in fields and not re.match(id_pattern, fields["id"]):
        raise FeedError(f"refusing an ID that doesn't match the source pattern: {fields['id']!r}")
    for value in fields.values():
        if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise FeedError(f"refusing a URL field with unexpected characters: {value!r}")
    return template.format(**fields)


class _AllowlistRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed: frozenset[str]) -> None:
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).hostname not in self.allowed:
            raise FeedError(f"refused a redirect to a host that isn't allowlisted: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(
        self,
        allowed_hosts: list[str],
        *,
        max_bytes: int = 20_000_000,
        timeout: float = 60,
        opener=None,
    ) -> None:
        self.allowed = frozenset(allowed_hosts)
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener(_AllowlistRedirects(self.allowed))
        self.requested: list[str] = []

    @classmethod
    def from_sources(cls, sources: dict, opener=None) -> Fetcher:
        http = sources["http"]
        return cls(
            http["allowed_hosts"],
            max_bytes=http.get("max_bytes", 20_000_000),
            timeout=http.get("timeout_seconds", 60),
            opener=opener,
        )

    def _open(self, url: str, range_bytes: int | None = None):
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in self.allowed:
            raise FeedError(f"refusing to fetch a URL outside the allowlist: {url}")
        headers = {"User-Agent": USER_AGENT}
        if range_bytes:
            headers["Range"] = f"bytes=0-{range_bytes - 1}"
        self.requested.append(url)
        try:
            return self._opener.open(
                urllib.request.Request(url, headers=headers), timeout=self.timeout
            )
        except (HTTPError, URLError, TimeoutError) as exc:
            raise FeedError(f"GET {url} failed: {exc}") from exc

    def exists(self, url: str) -> bool:
        """True if the URL is there, False on a 404. Any other failure raises FeedError."""
        try:
            with self._open(url):
                return True
        except FeedError as exc:
            if isinstance(exc.__cause__, HTTPError) and exc.__cause__.code == 404:
                return False
            raise

    def get(self, url: str, range_bytes: int | None = None) -> bytes:
        limit = range_bytes or self.max_bytes
        with self._open(url, range_bytes) as response:
            body = response.read(limit + 1)
        if len(body) > limit and not range_bytes:
            raise FeedError(f"response from {url} is larger than {limit} bytes")
        return body[:limit]

    def lines(self, url: str) -> Iterator[str]:
        """Stream a text file line by line; stop early by breaking out of the loop."""
        with self._open(url) as response:
            read = 0
            for raw in response:
                read += len(raw)
                if read > self.max_bytes:
                    raise FeedError(f"response from {url} is larger than {self.max_bytes} bytes")
                yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
