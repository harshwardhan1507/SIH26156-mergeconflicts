"""
Production Kafka Sink using kafka-python.

Gracefully degrades when kafka-python is not installed (air-gap safe).
Writes each UES event as UTF-8 JSON to a configured Kafka topic, keyed by event_id
for deterministic partition routing.

Usage:
    from ulpf.sinks.kafka_producer import KafkaProducerSink
    sink = KafkaProducerSink(
        topic="ulpf.events",
        bootstrap_servers=["kafka01:9092", "kafka02:9092"],
        compression_type="gzip",   # optional: "gzip", "snappy", "lz4"
        batch_size=16384,           # bytes
        linger_ms=10,
        retries=5,
    )
    sink.write(ues_event)
    sink.close()
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaProducer as _KafkaProducer
    from kafka.errors import KafkaError as _KafkaError
    _KAFKA_AVAILABLE = True
except ImportError:
    _KAFKA_AVAILABLE = False
    _KafkaProducer = None
    _KafkaError = Exception


class KafkaProducerSink(SinkBase):
    """
    Production Kafka sink.
    Falls back to NDJSON file output when kafka-python is not installed.
    """

    def __init__(
        self,
        topic: str,
        bootstrap_servers: list[str] | str = "localhost:9092",
        compression_type: str | None = "gzip",
        batch_size: int = 16384,
        linger_ms: int = 10,
        retries: int = 5,
        fallback_path: Path | str | None = None,
    ) -> None:
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.compression_type = compression_type
        self.batch_size = batch_size
        self.linger_ms = linger_ms
        self.retries = retries
        self._producer = None
        self._fallback_file = None
        self._written = 0
        self._errors = 0

        if _KAFKA_AVAILABLE:
            try:
                self._producer = _KafkaProducer(
                    bootstrap_servers=bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    compression_type=compression_type,
                    batch_size=batch_size,
                    linger_ms=linger_ms,
                    retries=retries,
                    acks="all",
                    enable_idempotence=True,
                )
                logger.info(
                    "KafkaProducerSink connected to %s → topic=%s",
                    bootstrap_servers, topic,
                )
            except Exception as exc:
                logger.warning(
                    "KafkaProducerSink: could not connect to Kafka (%s). "
                    "Falling back to local NDJSON file.", exc,
                )
                self._producer = None
        else:
            logger.warning(
                "kafka-python not installed. KafkaProducerSink will write to "
                "local fallback NDJSON. Install: pip install kafka-python"
            )

        # Fallback: write to local NDJSON when Kafka unavailable
        if self._producer is None:
            fb_path = Path(fallback_path or "output/kafka_events.ndjson")
            fb_path.parent.mkdir(parents=True, exist_ok=True)
            self._fallback_file = open(fb_path, "a", encoding="utf-8")
            logger.info("KafkaProducerSink fallback → %s", fb_path)

    def write(self, event: dict[str, Any]) -> None:
        event_id = event.get("event_id", "")
        if self._producer is not None:
            try:
                future = self._producer.send(
                    self.topic,
                    key=event_id,
                    value=event,
                )
                # Non-blocking — errors surface on flush/close
                future.add_errback(lambda exc: logger.error("Kafka send failed: %s", exc))
                self._written += 1
            except Exception as exc:
                logger.error("KafkaProducerSink.write error: %s", exc)
                self._errors += 1
        elif self._fallback_file:
            self._fallback_file.write(json.dumps(event, default=str) + "\n")
            self._written += 1

    def flush(self) -> None:
        if self._producer is not None:
            try:
                self._producer.flush(timeout=30)
                logger.debug("KafkaProducerSink flushed %d events", self._written)
            except Exception as exc:
                logger.error("KafkaProducerSink.flush error: %s", exc)
        elif self._fallback_file:
            self._fallback_file.flush()

    def close(self) -> None:
        self.flush()
        if self._producer is not None:
            try:
                self._producer.close(timeout=30)
            except Exception as exc:
                logger.warning("KafkaProducerSink.close error: %s", exc)
        if self._fallback_file:
            self._fallback_file.close()
        logger.info(
            "KafkaProducerSink closed — written=%d errors=%d",
            self._written, self._errors,
        )

    @property
    def is_kafka_connected(self) -> bool:
        return self._producer is not None

    @property
    def written_count(self) -> int:
        return self._written
