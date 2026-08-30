"""
Kafka Stub Sink.

Mimics a Kafka producer by writing Kafka-envelope records to a local NDJSON file.
Each record has the shape:
  {"topic": <topic>, "key": <event_id>, "value": <ues_event>}

To replace with a real Kafka producer:
  1. Install confluent-kafka or kafka-python.
  2. Subclass SinkBase and replace the write() logic.
  3. No changes to the rest of the pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase


class KafkaStubSink(SinkBase):
    def __init__(self, output_path: str | Path, topic: str = 'ulpf-events'):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.topic = topic
        self._fh = open(self.output_path, 'a', encoding='utf-8', buffering=1)
        self._count = 0

    def write(self, event: dict[str, Any]) -> None:
        record = {
            'topic': self.topic,
            'key': event.get('event_id', ''),
            'value': event,
        }
        self._fh.write(json.dumps(record, default=str) + '\n')
        self._count += 1

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    @property
    def records_written(self) -> int:
        return self._count
