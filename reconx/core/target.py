"""
ReconX Target
-------------

Target parsing, normalization, and validation.

DEV BY LORD MINATO
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..utils import (
    build_url,
    is_valid_hostname,
    normalize_target,
)


@dataclass(slots=True)
class Target:
    """
    Represents a ReconX assessment target.

    The object stores only normalized target information.
    """

    original: str
    hostname: str
    scheme: str = "https"
    port: int | None = None

    @classmethod
    def from_input(cls, value: str) -> "Target":
        """
        Create a Target from user input.

        Accepted examples:

            example.com
            https://example.com
            http://example.com
            https://example.com:8443
        """

        if not value or not value.strip():
            raise ValueError("Target cannot be empty.")

        original = value.strip()

        parsed_value = original

        if "://" not in parsed_value:
            parsed_value = f"//{parsed_value}"

        parsed = urlparse(
            parsed_value,
            scheme="https",
        )

        hostname = normalize_target(original)

        if not is_valid_hostname(hostname):
            raise ValueError(
                f"Invalid hostname: {hostname}"
            )

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            scheme = "https"

        port = parsed.port

        return cls(
            original=original,
            hostname=hostname,
            scheme=scheme,
            port=port,
        )

    @property
    def url(self) -> str:
        """Return the normalized target URL."""

        base = build_url(
            self.hostname,
            self.scheme,
        )

        if self.port is not None:
            return f"{base}:{self.port}"

        return base

    @property
    def display(self) -> str:
        """Return a human-readable target name."""

        return self.hostname

    @property
    def host_with_port(self) -> str:
        """Return hostname with port when one exists."""

        if self.port is None:
            return self.hostname

        return f"{self.hostname}:{self.port}"

    def __str__(self) -> str:
        return self.hostname
