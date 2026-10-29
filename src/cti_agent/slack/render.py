"""Untrusted text made safe to show in Slack: report quotes, feed fields, model output and
file names. Nothing shown can mention anyone, become a link, or hide a character.

Indicators are defanged (1[.]2[.]3[.]4, 2001[:]db8[:][:]1, hxxps://), Slack's markup
characters are escaped, and characters that are invisible, change direction or render as
blank are shown as their code points.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Candidates only: each is checked with the ipaddress module, so times such as 12:30:45 stay.
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b")
HASH = re.compile(r"[0-9A-Fa-f]{32,128}")
USER_ID = re.compile(r"[UW][A-Z0-9]{2,20}")
# By category: controls, format characters (zero-width, bidi, tags), private use, surrogates,
# unassigned, and line or paragraph separators. Then the blank-looking ones categories miss:
# the combining grapheme joiner, Hangul and Khmer fillers, the Mongolian vowel separator,
# the braille blank, and variation selectors.
HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}
BLANK = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2800, 0x3164, 0xFFA0}
VARIATION_SELECTORS = (range(0xFE00, 0xFE10), range(0xE0100, 0xE01F0))


def _hidden(ch: str) -> bool:
    if ch in "\t\n\r":
        return False
    point = ord(ch)
    return (
        unicodedata.category(ch) in HIDDEN_CATEGORIES
        or point in BLANK
        or any(point in r for r in VARIATION_SELECTORS)
    )


def show_hidden(text: str) -> str:
    return "".join(f"[U+{ord(c):04X}]" if _hidden(c) else c for c in text)


def _dots(text: str) -> str:
    return text.replace(".", "[.]")


def _is_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _ipv6(match: re.Match) -> str:
    text = match.group(0)
    return text.replace(":", "[:]") if _is_ipv6(text) else text


def _known(text: str, known: tuple[str, ...]) -> str:
    """The run's own indicator values, whatever their kind; hashes need nothing."""
    for value in sorted(set(known), key=len, reverse=True):
        if value and not HASH.fullmatch(value):
            text = text.replace(value, defang_value(value))
    return text


def defang(text: str, known: tuple[str, ...] = ()) -> str:
    """For prose: URLs, emails, IP addresses, anything shaped like a domain, and the run's
    own indicator values."""
    text = _known(text, known)
    text = URL.sub(lambda m: _dots(_scheme(m.group(0))), text)
    text = EMAIL.sub(lambda m: _dots(m.group(0).replace("@", "[@]")), text)
    text = IPV6.sub(_ipv6, text)
    text = IPV4.sub(lambda m: _dots(m.group(0)), text)
    return DOMAIN.sub(lambda m: _dots(m.group(0)), text)


def defang_code(text: str, known: tuple[str, ...] = ()) -> str:
    """For KQL and other code: URLs, IP addresses and the run's indicator values, but not
    every dotted name, so Table.Column and tostring(Data.id) stay readable."""
    text = _known(text, known)
    text = URL.sub(lambda m: _dots(_scheme(m.group(0))), text)
    text = IPV6.sub(_ipv6, text)
    return IPV4.sub(lambda m: _dots(m.group(0)), text)


def defang_markdown(text: str, known: tuple[str, ...] = ()) -> str:
    """For a document such as brief.md: prose defanged as prose, fenced code as code."""
    parts = text.split("```")
    return "```".join(
        defang_code(part, known) if n % 2 else defang(part, known) for n, part in enumerate(parts)
    )


def defang_value(value: str) -> str:
    if _is_ipv6(value):
        return value.replace(":", "[:]")
    return _dots(_scheme(value).replace("@", "[@]"))


def _scheme(url: str) -> str:
    return re.sub(r"(?i)^http", lambda m: "hxxp" if m.group(0).islower() else "HXXP", url)


def escape(text: str) -> str:
    """Slack's own escaping: with < > & escaped, text can't form a mention, a channel ping
    or a link."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fit(text: str, limit: int) -> str:
    """Cut to Slack's limit, never through the middle of an &amp; escape."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    amp = cut.rfind("&", max(0, len(cut) - 5))
    if amp != -1 and ";" not in cut[amp:]:
        cut = cut[:amp]
    return cut + "…"


def mrkdwn(text: str, limit: int = 2900, known: tuple[str, ...] = ()) -> str:
    """Untrusted text for a mrkdwn field."""
    return fit(escape(defang(show_hidden(text or ""), known)), limit)


def plain(text: str, limit: int = 150, known: tuple[str, ...] = ()) -> str:
    """Untrusted text for a plain_text field, which Slack shows literally."""
    return fit(defang(show_hidden(text or ""), known), limit)


def code(text: str, limit: int = 2900, known: tuple[str, ...] = ()) -> str:
    """Code in a fenced block, which Slack never turns into links."""
    body = escape(defang_code(show_hidden(text or ""), known)).replace("```", "ˋˋˋ")
    return "```" + fit(body, limit - 6) + "```"


def first_lines(text: str, n: int) -> tuple[str, int]:
    """The first n lines, and how many more there are."""
    lines = (text or "").splitlines()
    return "\n".join(lines[:n]), max(0, len(lines) - n)


def mention(user_id: str) -> str:
    return f"<@{user_id}>" if USER_ID.fullmatch(user_id or "") else ""
