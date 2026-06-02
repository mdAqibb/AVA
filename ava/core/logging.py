"""Structured (JSON-lines) logging plus a human-readable console mirror.

Every run gets a dedicated log file under the run directory. Log records are
JSON objects, one per line, so runs are machine-parseable and grep-able.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach any structured extras passed via logger.info(..., extra={"ctx": {...}})
        ctx = getattr(record, "ctx", None)
        if ctx:
            payload["ctx"] = ctx
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name: str = "ava") -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(log_file: Path, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("ava")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s",
                                            datefmt="%H:%M:%S"))
    logger.addHandler(console)
    return logger


def log(logger: logging.Logger, level: int, msg: str, **ctx) -> None:
    """Helper to attach structured context cleanly."""
    logger.log(level, msg, extra={"ctx": ctx} if ctx else None)
