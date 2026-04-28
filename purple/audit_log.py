"""Append-only JSONL audit log.

Every envelope and every state transition is recorded. A campaign can be
fully reconstructed from the log.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .envelope import Envelope


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append_envelope(self, envelope: Envelope) -> None:
        self._write({"kind": "envelope", "data": envelope.to_jsonable()})

    def append_event(self, kind: str, **fields: Any) -> None:
        self._write({"kind": kind, **fields})

    def _write(self, record: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
