"""The bot's log: IDs and outcomes only, and never a token, whoever logs it (including the
Slack libraries at debug level)."""

from __future__ import annotations

import logging
import re

SECRETS = re.compile(
    r"xox[a-z]-[A-Za-z0-9-]+|xapp-[A-Za-z0-9-]+|Bearer\s+[A-Za-z0-9._~+/=-]+|ticket=[^&\s\"']+"
)


class Redact(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = SECRETS.sub("[redacted]", record.getMessage())
        record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(Redact())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
