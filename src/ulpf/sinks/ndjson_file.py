"""
Newline-Delimited JSON (NDJSON) File Sink.
Buffers writes and flushes on close or explicit flush().
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase


class NDJSONFileSink(SinkBase):
    def __init__(self, output_path: str | Path, buffer_size: int = 100):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.output_path, 'a', encoding='utf-8', buffering=1)
        self._count = 0

    def write(self, event: dict[str, Any]) -> None:
        self._fh.write(json.dumps(event, default=str) + '\n')
        self._count += 1

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    @property
    def events_written(self) -> int:
        return self._count
