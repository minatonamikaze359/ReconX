"""
ReconX Security Headers
-----------------------

Analyzes HTTP response security headers and provides
defensive configuration observations.

DEV BY LORD MINATO
"""

from __future__ import annotations

from typing import Any

import requests

from ..config import DEFAULT_TIMEOUT, USER_AGENT
from ..core.target import Target


class HeadersModule:
    name = "headers"
    description = "Security Headers"

    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HSTS",
            "description": (
                "Enforces HTTPS connections in supported browsers."
            ),
        },
        "content-security-policy": {
            "name": "Content-Security-Policy",
            "description": (
                "Controls which resources browsers may load."
            ),
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "description": (
                "Helps prevent MIME-type sniffing."
            ),
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "description": (
                "Controls whether pages can be embedded in frames."
            ),
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "description": (
                "Controls referrer information sent by browsers."
            ),
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "description": (
                "Controls access to selected browser capabilities."
            ),
        },
        "cross-origin-opener-policy": {
            "name": "Cross-Origin-Opener-Policy",
            "description": (
                "Controls cross-origin browsing context relationships."
            ),
        },
        "cross-origin-resource-policy": {
            "name": "Cross-Origin-Resource-Policy",
            "description": (
                "Controls which origins may load resources."
            ),
        },
        "cross-origin-embedder-policy": {
            "name": "Cross-Origin-Embedder-Policy",
            "description": (
                "Controls cross-origin resource embedding."
            ),
        },
    }

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            }
        )

    def fetch_headers(
        self,
        url: str,
    ) -> dict[str, Any]:
        try:
            response = self.session.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                stream=True,
            )

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            result = {
                "success": True,
                "status_code": response.status_code,
                "requested_url": url,
                "final_url": response.url,
                "headers": headers,
            }

            response.close()

            return result

        except requests.RequestException as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    def analyze(
        self,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []

        for header, metadata in self.SECURITY_HEADERS.items():
            value = headers.get(header)

            if value:
                findings.append(
                    {
                        "header": metadata["name"],
                        "present": True,
                        "value": value,
                        "description": metadata[
                            "description"
                        ],
                    }
                )
            else:
                findings.append(
                    {
                        "header": metadata["name"],
                        "present": False,
                        "value": None,
                        "description": metadata[
                            "description"
                        ],
                    }
                )

        present = [
            item
            for item in findings
            if item["present"]
        ]

        missing = [
            item
            for item in findings
            if not item["present"]
        ]

        return {
            "checked": len(findings),
            "present": len(present),
            "missing": len(missing),
            "findings": findings,
        }

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        response = self.fetch_headers(
            target.url
        )

        if not response.get("success"):
            return {
                "target": target.hostname,
                "status": "failed",
                "error": response.get("error"),
                "headers": {},
                "analysis": {},
            }

        headers = response.get(
            "headers",
            {},
        )

        analysis = self.analyze(
            headers
        )

        return {
            "target": target.hostname,
            "status": "success",
            "status_code": response.get(
                "status_code"
            ),
            "requested_url": response.get(
                "requested_url"
            ),
            "final_url": response.get(
                "final_url"
            ),
            "headers": headers,
            "analysis": analysis,
        }
