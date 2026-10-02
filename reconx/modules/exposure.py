"""
ReconX Exposure Intelligence
----------------------------

Performs defensive exposure analysis using information
already observable through normal HTTP/TLS/DNS responses.

This module does NOT exploit vulnerabilities, brute-force
paths, bypass controls, or attempt unauthorized access.

DEV BY LORD MINATO
"""

from __future__ import annotations

from typing import Any

import requests

from ..config import DEFAULT_TIMEOUT, USER_AGENT
from ..core.target import Target


class ExposureModule:
    name = "exposure"
    description = "Exposure Analysis"

    SENSITIVE_HEADERS = {
        "server": "Server technology disclosure",
        "x-powered-by": "Runtime technology disclosure",
        "x-aspnet-version": "ASP.NET version disclosure",
        "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    }

    INTERESTING_PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
    )

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
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
                "url": response.url,
                "headers": headers,
            }

            response.close()

            return result

        except requests.RequestException as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    def check_public_resources(
        self,
        target: Target,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        base_url = target.url.rstrip("/")

        for path in self.INTERESTING_PATHS:
            url = f"{base_url}{path}"

            try:
                response = self.session.get(
                    url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    stream=True,
                )

                status_code = response.status_code
                final_url = response.url
                content_type = response.headers.get(
                    "Content-Type"
                )

                response.close()

                if status_code == 200:
                    findings.append(
                        {
                            "type": "public_resource",
                            "severity": "info",
                            "path": path,
                            "status_code": status_code,
                            "url": final_url,
                            "content_type": content_type,
                            "description": (
                                "Publicly accessible resource "
                                "was observed."
                            ),
                        }
                    )

                elif status_code in {
                    401,
                    403,
                }:
                    findings.append(
                        {
                            "type": "public_resource",
                            "severity": "info",
                            "path": path,
                            "status_code": status_code,
                            "url": final_url,
                            "content_type": content_type,
                            "description": (
                                "Resource exists or is handled "
                                "by the server but access is restricted."
                            ),
                        }
                    )

            except requests.RequestException:
                continue

        return findings

    def analyze_headers(
        self,
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for header, description in self.SENSITIVE_HEADERS.items():
            value = headers.get(header)

            if not value:
                continue

            findings.append(
                {
                    "type": "information_disclosure",
                    "severity": "low",
                    "header": header,
                    "value": value,
                    "description": description,
                }
            )

        return findings

    @staticmethod
    def analyze_transport(
        target: Target,
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if target.scheme != "https":
            findings.append(
                {
                    "type": "transport",
                    "severity": "medium",
                    "issue": "HTTP target",
                    "description": (
                        "The requested target uses HTTP rather "
                        "than HTTPS."
                    ),
                }
            )

        if (
            target.scheme == "https"
            and "strict-transport-security" not in headers
        ):
            findings.append(
                {
                    "type": "transport",
                    "severity": "low",
                    "issue": "HSTS not observed",
                    "description": (
                        "Strict-Transport-Security was not "
                        "observed in the response."
                    ),
                }
            )

        return findings

    @staticmethod
    def build_summary(
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        severity_counts = {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
        }

        for finding in findings:
            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            ).lower()

            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        }

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "target": target.hostname,
            "status": "success",
            "findings": [],
        }

        response = self.fetch_headers(
            target.url
        )

        if not response.get("success"):
            result["status"] = "failed"
            result["error"] = response.get(
                "error"
            )
            return result

        headers = response.get(
            "headers",
            {},
        )

        findings: list[dict[str, Any]] = []

        findings.extend(
            self.analyze_headers(headers)
        )

        findings.extend(
            self.analyze_transport(
                target,
                headers,
            )
        )

        findings.extend(
            self.check_public_resources(
                target
            )
        )

        result["status_code"] = response.get(
            "status_code"
        )

        result["final_url"] = response.get(
            "url"
        )

        result["findings"] = findings

        result["summary"] = self.build_summary(
            findings
        )

        return result
