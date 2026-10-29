"""Button values and modal metadata: small versioned JSON, decoded strictly on the way back.

Slack returns them as they were sent, but a click is still input, so unknown keys, wrong
types and malformed run IDs are refused.
"""

from __future__ import annotations

import json

from cti_agent.slack.grammar import RUN_ID

MAX_VALUE = 2000  # a button's value
MAX_METADATA = 3000  # a modal's private_metadata
FIELDS = {
    "v": int,  # version
    "r": str,  # run ID
    "i": str,  # item ref
    "h": str,  # item hash shown
    "s": str,  # status shown
    "d": str,  # digest of a list or a publish plan
    "n": int,  # a count
    "a": str,  # what to do
    "k": str,  # STIX kind
    "c": str,  # channel
    "t": str,  # message ts
    "ids": list,  # advisory IDs
}


def encode(limit: int = MAX_VALUE, **fields) -> str:
    text = json.dumps({"v": 1, **fields}, separators=(",", ":"))
    if len(text) > limit:
        raise ValueError(f"value too long for Slack ({len(text)} > {limit} characters)")
    return text


def decode(text: str | None, *required: str) -> dict | None:
    try:
        data = json.loads(text or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("v") != 1:
        return None
    for key, value in data.items():
        kind = FIELDS.get(key)
        if kind is None or isinstance(value, bool) or not isinstance(value, kind):
            return None
        if kind is list and not all(isinstance(x, str) for x in value):
            return None
    if any(key not in data for key in required):
        return None
    if "r" in data and not RUN_ID.fullmatch(data["r"]):
        return None
    return data
