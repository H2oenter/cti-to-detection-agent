"""What the bot needs from Slack, as a small interface. app.py implements it with Slack's
web client; tests use a fake that records every call."""

from __future__ import annotations

from typing import Protocol


class SlackPort(Protocol):
    def post(
        self, channel: str, blocks: list[dict], text: str, thread_ts: str | None = None
    ) -> str:
        """Post a message with link and media previews off; returns its ts."""

    def update(self, channel: str, ts: str, blocks: list[dict], text: str) -> None: ...

    def upload_text(
        self, channel: str, thread_ts: str | None, filename: str, content: str, title: str
    ) -> None: ...

    def open_view(self, trigger_id: str, view: dict) -> None: ...

    def file_info(self, file_id: str) -> dict: ...
