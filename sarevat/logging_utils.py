"""Auditoria estructurada con redaccion y rotacion."""

from __future__ import annotations

import json
import logging
import os
from contextlib import suppress
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from sarevat.security import redact_text


class AuditLogger:
    def __init__(self, directory: Path, *, max_bytes: int = 2_000_000, backup_count: int = 10) -> None:
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "audit.jsonl"
        self._logger = logging.getLogger(f"sarevat.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        handler = RotatingFileHandler(
            self.path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)
        self._restrict_permissions(self.path)

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        with suppress(OSError):
            os.chmod(path, 0o600)

    def event(self, event: str, **data: Any) -> None:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **data,
        }
        safe = redact_text(json.dumps(payload, ensure_ascii=False, default=str))
        self._logger.info(safe)

    def close(self) -> None:
        for handler in tuple(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)
