"""
ReconX HTTP Intelligence
------------------------

Performs low-impact HTTP/HTTPS analysis against an
authorized target.

Collects:
    - HTTP status
    - Final URL
    - Redirect information
    - Response headers
    - Content type
    - Content length
    - Response timing
    - HTTP version
    - Server information

DEV BY LORD MINATO
"""

from __future__ import annotations

import time
from typing import Any

import requests

from ..config import DEFAULT_TIMEOUT, MAX_REDIRECTS, USER_AGENT
from ..core.target import Target


class HTTPModule:
    name = "http"
    description = "HTTP Analysis"

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.9,*/*;q=0.8"
                ),
            }
        )

        self.session.max_redirects = MAX_REDIRECTS

    def request(
        self,
        url: str,
    ) -> dict[str, Any]:
        started = time.perf_counter()

        try:
            response = self.session.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                stream=True,
            )

            elapsed = time.perf_counter() - started

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            content_length = headers.get(
                "content-length"
            )

            try:
                content_length_value = (
                    int(content_length)
                    if content_length
                    else None
                )
            except ValueError:
                content_length_value = None

            redirect_chain = [
                {
                    "status": item.status_code,
                    "url": item.url,
                    "location": item.headers.get(
                        "Location"
                    ),
                }
                for item in response.history
            ]

            result = {
                "status": "success",
                "status_code": response.status_code,
                "reason": response.reason,
                "requested_url": url,
                "final_url": response.url,
                "response_time_seconds": round(
                    elapsed,
                    4,
                ),
                "redirect_count": len(
                    response.history
                ),
                "redirects": redirect_chain,
                "http_version": (
                    getattr(
                        response.raw,
                        "version",
                        None,
                    )
                ),
                "content_type": headers.get(
                    "content-type"
                ),
                "content_length": content_length_value,
                "server": headers.get(
                    "server"
                ),
                "headers": headers,
            }

            response.close()

            return result

        except requests.TooManyRedirects as exc:
            return {
                "status": "failed",
                "error": (
                    "Too many redirects encountered."
                ),
                "details": str(exc),
                "requested_url": url,
            }

        except requests.Timeout as exc:
            return {
                "status": "failed",
                "error": "HTTP request timed out.",
                "details": str(exc),
                "requested_url": url,
            }

        except requests.RequestException as exc:
            return {
                "status": "failed",
                "error": "HTTP request failed.",
                "details": str(exc),
                "requested_url": url,
            }

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        hostname = target.hostname

        https_url = target.url

        result: dict[str, Any] = {
            "target": hostname,
            "checks": {},
        }

        # Primary request using the target's configured scheme.
        primary = self.request(https_url)

        result["checks"]["primary"] = primary

        # If HTTPS failed, perform a normal HTTP check.
        if (
            target.scheme == "https"
            and primary.get("status") != "success"
        ):
            http_url = f"http://{hostname}"

            result["checks"]["http_fallback"] = (
                self.request(http_url)
            )

        # Useful summary for later report generation.
        successful_checks = [
            name
            for name, data in result["checks"].items()
            if data.get("status") == "success"
        ]

        result["summary"] = {
            "checks_performed": len(
                result["checks"]
            ),
            "successful_checks": len(
                successful_checks
            ),
            "successful_protocols": (
                successful_checks
            ),
        }

        return result
