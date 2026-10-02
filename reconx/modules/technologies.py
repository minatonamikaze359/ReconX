"""
ReconX Technology Intelligence
------------------------------

Detects common web technologies using passive indicators
from HTTP headers and HTML content.

DEV BY LORD MINATO
"""

from __future__ import annotations

import re
from typing import Any

import requests
from bs4 import BeautifulSoup

from ..config import DEFAULT_TIMEOUT, USER_AGENT
from ..core.target import Target


class TechnologyModule:
    name = "technologies"
    description = "Technology Detection"

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            }
        )

    @staticmethod
    def detect_headers(
        headers: dict[str, str],
    ) -> list[dict[str, str]]:
        technologies: list[dict[str, str]] = []

        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        generator = headers.get("x-generator", "")

        if server:
            technologies.append(
                {
                    "technology": server,
                    "category": "Server",
                    "source": "Server header",
                }
            )

        if powered_by:
            technologies.append(
                {
                    "technology": powered_by,
                    "category": "Runtime",
                    "source": "X-Powered-By header",
                }
            )

        if generator:
            technologies.append(
                {
                    "technology": generator,
                    "category": "CMS",
                    "source": "X-Generator header",
                }
            )

        return technologies

    @staticmethod
    def detect_html(
        html: str,
    ) -> list[dict[str, str]]:
        technologies: list[dict[str, str]] = []

        if not html:
            return technologies

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

        generator = soup.find(
            "meta",
            attrs={
                "name": re.compile(
                    r"^generator$",
                    re.I,
                )
            },
        )

        if generator:
            content = generator.get(
                "content",
                "",
            )

            if content:
                technologies.append(
                    {
                        "technology": str(content),
                        "category": "CMS",
                        "source": "HTML generator meta tag",
                    }
                )

        html_lower = html.lower()

        signatures = [
            (
                "WordPress",
                "CMS",
                [
                    "wp-content/",
                    "wp-includes/",
                    "wordpress",
                ],
            ),
            (
                "Drupal",
                "CMS",
                [
                    "drupal-settings-json",
                    "/sites/default/",
                    "drupal",
                ],
            ),
            (
                "Joomla",
                "CMS",
                [
                    "/media/system/js/",
                    "joomla",
                ],
            ),
            (
                "Next.js",
                "Framework",
                [
                    "__next_data__",
                    "/_next/",
                ],
            ),
            (
                "Nuxt",
                "Framework",
                [
                    "__nuxt__",
                    "/_nuxt/",
                ],
            ),
            (
                "React",
                "JavaScript Framework",
                [
                    "react",
                    "react-dom",
                ],
            ),
            (
                "Vue.js",
                "JavaScript Framework",
                [
                    "vue.js",
                    "vue.min.js",
                ],
            ),
            (
                "Angular",
                "JavaScript Framework",
                [
                    "ng-version",
                    "angular",
                ],
            ),
            (
                "jQuery",
                "JavaScript Library",
                [
                    "jquery",
                    "jquery.min.js",
                ],
            ),
            (
                "Bootstrap",
                "CSS Framework",
                [
                    "bootstrap.min.css",
                    "bootstrap.css",
                ],
            ),
            (
                "Tailwind CSS",
                "CSS Framework",
                [
                    "tailwindcss",
                    "tailwind.min.css",
                ],
            ),
        ]

        for technology, category, markers in signatures:
            if any(
                marker in html_lower
                for marker in markers
            ):
                technologies.append(
                    {
                        "technology": technology,
                        "category": category,
                        "source": "HTML content",
                    }
                )

        return technologies

    @staticmethod
    def deduplicate(
        technologies: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        seen: set[tuple[str, str]] = set()
        result: list[dict[str, str]] = []

        for item in technologies:
            key = (
                item.get("technology", "").lower(),
                item.get("category", "").lower(),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(item)

        return result

    def fetch_page(
        self,
        url: str,
    ) -> dict[str, Any]:
        try:
            response = self.session.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
            )

            return {
                "success": True,
                "url": response.url,
                "status_code": response.status_code,
                "headers": {
                    key.lower(): value
                    for key, value in response.headers.items()
                },
                "html": response.text,
            }

        except requests.RequestException as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        page = self.fetch_page(
            target.url
        )

        if not page.get("success"):
            return {
                "target": target.hostname,
                "status": "failed",
                "error": page.get("error"),
                "technologies": [],
                "count": 0,
            }

        headers = page.get(
            "headers",
            {},
        )

        html = page.get(
            "html",
            "",
        )

        detected = []

        detected.extend(
            self.detect_headers(headers)
        )

        detected.extend(
            self.detect_html(html)
        )

        technologies = self.deduplicate(
            detected
        )

        return {
            "target": target.hostname,
            "status": "success",
            "url": page.get("url"),
            "status_code": page.get(
                "status_code"
            ),
            "technologies": technologies,
            "count": len(technologies),
        }
