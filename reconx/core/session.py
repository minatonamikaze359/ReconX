"""
ReconX Scan Session
-------------------

Tracks the lifecycle and results of a ReconX scan.

DEV BY LORD MINATO
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def current_utc() -> datetime:
    """Return the current UTC datetime."""

    return datetime.now(timezone.utc)


@dataclass
class ScanSession:
    """
    Represents one ReconX scan session.
    """

    target: str
    modules: list[str] = field(default_factory=list)

    started_at: datetime = field(
        default_factory=current_utc
    )

    finished_at: datetime | None = None

    status: str = "initialized"

    results: dict[str, Any] = field(
        default_factory=dict
    )

    errors: list[dict[str, str]] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def start(self) -> None:
        """Mark the session as running."""

        self.started_at = current_utc()
        self.status = "running"

    def complete(self) -> None:
        """Mark the session as completed."""

        self.finished_at = current_utc()
        self.status = "completed"

    def fail(self, message: str) -> None:
        """
        Mark the session as failed and record the error.
        """

        self.finished_at = current_utc()
        self.status = "failed"

        self.add_error(
            module="engine",
            message=message,
        )

    def add_result(
        self,
        module: str,
        result: Any,
    ) -> None:
        """
        Store the result returned by a module.
        """

        self.results[module] = result

    def add_error(
        self,
        module: str,
        message: str,
    ) -> None:
        """
        Record an error without necessarily stopping
        the entire scan.
        """

        self.errors.append(
            {
                "module": module,
                "message": message,
            }
        )

    @property
    def duration_seconds(self) -> float | None:
        """Return scan duration in seconds."""

        if self.finished_at is None:
            return None

        return (
            self.finished_at - self.started_at
        ).total_seconds()

    @property
    def successful_modules(self) -> list[str]:
        """Return modules that produced results."""

        return [
            module
            for module in self.results
            if module not in {
                error["module"]
                for error in self.errors
            }
        ]

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the session into a JSON-friendly dictionary.
        """

        return {
            "target": self.target,
            "modules": self.modules,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat()
                if self.finished_at
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "results": self.results,
            "errors": self.errors,
            "metadata": self.metadata,
        }
