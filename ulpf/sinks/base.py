"""Abstract base class for all output sinks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SinkBase(ABC):
    @abstractmethod
    def write(self, event: dict[str, Any]) -> None:
        """Write a single normalized UES event to the sink."""

    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered writes. Called at end of pipeline run."""

    def close(self) -> None:
        """Optional cleanup. Override if needed."""
        self.flush()
