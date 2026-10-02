"""
ReconX DNS Intelligence
-----------------------

Collects DNS records for an authorized target.

Supported records:
    A
    AAAA
    CNAME
    MX
    NS
    TXT
    SOA

DEV BY LORD MINATO
"""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from ..config import DEFAULT_TIMEOUT
from ..core.target import Target
from ..utils import unique_items


class DNSModule:
    """ReconX DNS intelligence module."""

    name = "dns"
    description = "DNS Intelligence"

    RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
    )

    def __init__(self) -> None:
        self.resolver = dns.resolver.Resolver()

        self.resolver.timeout = DEFAULT_TIMEOUT
        self.resolver.lifetime = DEFAULT_TIMEOUT

    def query(
        self,
        hostname: str,
        record_type: str,
    ) -> list[str]:
        """
        Query a DNS record type.

        Returns an empty list when the record does not exist
        or the DNS server does not provide an answer.
        """

        try:
            answers = self.resolver.resolve(
                hostname,
                record_type,
            )

            records: list[str] = []

            for answer in answers:
                records.append(
                    answer.to_text()
                )

            return unique_items(records)

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []

        except Exception:
            return []

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        """
        Run DNS intelligence against the target.
        """

        hostname = target.hostname

        results: dict[str, Any] = {
            "target": hostname,
            "records": {},
        }

        for record_type in self.RECORD_TYPES:
            records = self.query(
                hostname,
                record_type,
            )

            results["records"][
                record_type
            ] = records

        results["summary"] = self.build_summary(
            results["records"]
        )

        return results

    @staticmethod
    def build_summary(
        records: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Build a compact DNS summary."""

        total_records = sum(
            len(values)
            for values in records.values()
        )

        populated_types = [
            record_type
            for record_type, values
            in records.items()
            if values
        ]

        return {
            "total_records": total_records,
            "record_types_found": populated_types,
            "record_types_checked": len(
                records
            ),
        }
