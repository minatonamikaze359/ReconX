"""
ReconX Utilities
----------------

Shared helper functions used throughout ReconX.

DEV BY LORD MINATO
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse


def utc_timestamp() -> str:
    """
    Return the current UTC time in ISO-8601 format.
    """

    return datetime.now(timezone.utc).isoformat()


def normalize_target(target: str) -> str:
    """
    Normalize a user-provided target.

    Examples:
        example.com
        https://example.com
        http://example.com/path

    Returns:
        A normalized hostname.
    """

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    # Add a temporary scheme so urlparse handles plain domains.
    value = target

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            f"Unable to determine hostname from target: {target}"
        )

    return hostname.rstrip(".").lower()


def build_url(target: str, scheme: str = "https") -> str:
    """
    Build a clean URL from a hostname.

    Args:
        target: Domain or hostname.
        scheme: http or https.

    Returns:
        Normalized URL.
    """

    hostname = normalize_target(target)

    if scheme not in {"http", "https"}:
        raise ValueError(
            "Scheme must be either 'http' or 'https'."
        )

    return f"{scheme}://{hostname}"


def is_valid_hostname(hostname: str) -> bool:
    """
    Perform basic hostname validation.

    This intentionally validates syntax only. It does not
    determine whether the host exists on the internet.
    """

    hostname = hostname.strip().rstrip(".")

    if not hostname or len(hostname) > 253:
        return False

    # IPv4 addresses are accepted.
    ipv4_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if ipv4_pattern.match(hostname):
        parts = hostname.split(".")

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    # Standard hostname validation.
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return bool(hostname_pattern.match(hostname))


def safe_filename(value: str) -> str:
    """
    Convert a string into a filesystem-safe filename.
    """

    value = value.strip()

    value = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value,
    )

    value = value.strip("._")

    return value or "unknown"


def format_duration(seconds: float) -> str:
    """
    Convert seconds into a human-readable duration.
    """

    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"

    if seconds < 60:
        return f"{seconds:.2f}s"

    minutes = int(seconds // 60)
    remaining = seconds % 60

    return f"{minutes}m {remaining:.1f}s"


def unique_items(items: list[str]) -> list[str]:
    """
    Remove duplicates while preserving original order.
    """

    seen: set[str] = set()
    result: list[str] = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result
