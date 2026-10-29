"""Downloading a report someone uploaded to the channel.

Only from files.slack.com over https, and checked against files.info before anything is
fetched. The bot token goes to that host alone: it's attached so it can't follow a
redirect, and redirects are refused anyway. The saved name is Slack's file ID, so the
uploaded file name never becomes a path or reaches a prompt.
"""

from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from cti_agent.inputs import HTML_SUFFIXES, MAX_BYTES, TEXT_SUFFIXES

HOST = "files.slack.com"
SUFFIXES = {".pdf", *HTML_SUFFIXES, *TEXT_SUFFIXES}
FILE_ID = re.compile(r"F[A-Z0-9]{6,20}")


class DownloadError(Exception):
    pass


@dataclass(frozen=True)
class Upload:
    file_id: str
    name: str  # as uploaded: shown escaped, never used as a path or in a prompt
    suffix: str
    size: int
    url: str


def check_file(info: dict) -> Upload | str:
    """What to download, or why not, from files.info alone."""
    file_id, name = info.get("id", ""), info.get("name") or ""
    suffix, size = Path(name).suffix.lower(), info.get("size")
    url = info.get("url_private_download") or ""
    if not FILE_ID.fullmatch(file_id):
        return "that doesn't look like a Slack file"
    if info.get("mode") != "hosted" or info.get("is_external"):
        return "only files uploaded to Slack can be ingested, not links to other storage"
    if suffix not in SUFFIXES:
        return "only PDF, HTML or text reports can be ingested"
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_BYTES:
        return "the file is empty or larger than 50 MB"
    if not slack_url(url):
        return "Slack didn't give a download link on files.slack.com"
    return Upload(file_id, name, suffix, size, url)


def slack_url(url: str) -> bool:
    parts = urlsplit(url)
    return (
        parts.scheme == "https"
        and parts.hostname == HOST
        and parts.port is None
        and not parts.username
        and not parts.password
    )


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DownloadError(f"Slack redirected the download (HTTP {code}), so nothing was saved")


def download(upload: Upload, token: str, dest_dir: Path, *, opener=None) -> Path:
    if not slack_url(upload.url) or not FILE_ID.fullmatch(upload.file_id):
        raise DownloadError("refusing to download from anywhere but files.slack.com")
    request = urllib.request.Request(upload.url, method="GET")
    request.add_unredirected_header("Authorization", f"Bearer {token}")
    opener = opener or urllib.request.build_opener(_NoRedirects())
    try:
        with opener.open(request, timeout=60) as response:
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        raise DownloadError(f"Slack answered HTTP {exc.code} for the file") from None
    except URLError:
        raise DownloadError(f"couldn't reach {HOST}") from None
    if len(data) != upload.size:
        raise DownloadError(
            "the download isn't the size Slack listed (perhaps a sign-in page instead of "
            "the file), so nothing was saved"
        )
    if problem := _content_problem(upload.suffix, data):
        raise DownloadError(problem)
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{upload.file_id}{upload.suffix}"
    part = path.with_name(path.name + ".part")
    part.write_bytes(data)
    part.replace(path)
    return path


def _content_problem(suffix: str, data: bytes) -> str | None:
    head = data[:512].lstrip().lower()
    if suffix == ".pdf" and not data.startswith(b"%PDF-"):
        return "the file is named .pdf but isn't a PDF, so nothing was saved"
    if suffix in TEXT_SUFFIXES and head.startswith((b"<!doctype html", b"<html")):
        return "the file is named as text but is a web page, so nothing was saved"
    return None
