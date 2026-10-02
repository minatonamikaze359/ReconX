"""
ReconX Subdomain Intelligence
-----------------------------

Passive subdomain discovery using Certificate Transparency
data from crt.sh.

DEV BY LORD MINATO
"""

from __future__ import annotations

from typing import Any

import requests

from ..config import DEFAULT_TIMEOUT, USER_AGENT
from ..core.target import Target
from ..utils import unique_items


class SubdomainModule:
    """ReconX passive subdomain discovery module."""

    name = "subdomains"
    description = "Passive Subdomain Discovery"

    CRTSH_URL = "https://crt.sh/"

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            }
        )

    def fetch_certificates(
        self,
        hostname: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve Certificate Transparency entries
        for the target domain.
        """

        try:
            response = self.session.get(
                self.CRTSH_URL,
                params={
                    "q": f"%.{hostname}",
                    "output": "json",
                },
                timeout=DEFAULT_TIMEOUT,
            )

            response.raise_for_status()

            data = response.json()

            if not isinstance(data, list):
                return []

            return data

        except (
            requests.RequestException,
            ValueError,
        ):
            return []

    @staticmethod
    def extract_names(
        certificates: list[dict[str, Any]],
        hostname: str,
    ) -> list[str]:
        """
        Extract valid hostnames from CT results.
        """

        discovered: list[str] = []

        suffix = f".{hostname}"

        for certificate in certificates:
            name_value = certificate.get(
                "name_value",
                "",
            )

            if not isinstance(
                name_value,
                str,
            ):
                continue

            for name in name_value.splitlines():
                name = name.strip().lower()

                # Remove wildcard notation.
                name = name.removeprefix("*.")

                if not name:
                    continue

                if name == hostname:
                    continue

                if name.endswith(suffix):
                    discovered.append(name)

        return sorted(
            unique_items(discovered)
        )

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        """
        Perform passive subdomain discovery.
        """

        hostname = target.hostname

        certificates = self.fetch_certificates(
            hostname
        )

        subdomains = self.extract_names(
            certificates,
            hostname,
        )

        return {
            "target": hostname,
            "source": "Certificate Transparency",
            "provider": "crt.sh",
            "subdomains": subdomains,
            "count": len(subdomains),
            "certificates_observed": len(
                certificates
            ),
        }
