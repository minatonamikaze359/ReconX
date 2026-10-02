"""
ReconX Endpoint Intelligence
----------------------------

Performs low-impact endpoint discovery from publicly
accessible HTML resources.

Sources include:
    - Links
    - Forms
    - Scripts
    - Stylesheets
    - Images
    - Metadata URLs

No brute-force or intrusive endpoint scanning is performed.

DEV BY LORD MINATO
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..config import DEFAULT_TIMEOUT, USER_AGENT
from ..core.target import Target
from ..utils import unique_items


class EndpointModule:
    name = "endpoints"
    description = "Endpoint Discovery"

    def __init__(self) -> None:
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            }
        )

    @staticmethod
    def is_same_host(
        url: str,
        hostname: str,
    ) -> bool:
        parsed = urlparse(url)

        return (
            parsed.hostname or ""
        ).lower() == hostname.lower()

    @staticmethod
    def normalize_url(
        url: str,
    ) -> str:
        parsed = urlparse(url)

        return parsed._replace(
            fragment=""
        ).geturl()

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
                "html": response.text,
            }

        except requests.RequestException as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    def extract_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
    ) -> list[str]:
        links: list[str] = []

        for element in soup.find_all(
            "a",
            href=True,
        ):
            href = str(
                element.get("href", "")
            ).strip()

            if not href:
                continue

            absolute = urljoin(
                base_url,
                href,
            )

            links.append(
                self.normalize_url(absolute)
            )

        return links

    def extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str,
    ) -> list[dict[str, Any]]:
        forms: list[dict[str, Any]] = []

        for form in soup.find_all("form"):
            action = str(
                form.get("action", "")
            ).strip()

            method = str(
                form.get("method", "GET")
            ).upper()

            if action:
                action_url = urljoin(
                    base_url,
                    action,
                )
            else:
                action_url = base_url

            inputs: list[dict[str, str]] = []

            for field in form.find_all(
                ["input", "textarea", "select"]
            ):
                name = str(
                    field.get("name", "")
                )

                field_type = str(
                    field.get(
                        "type",
                        field.name or "text",
                    )
                )

                if name:
                    inputs.append(
                        {
                            "name": name,
                            "type": field_type,
                        }
                    )

            forms.append(
                {
                    "action": self.normalize_url(
                        action_url
                    ),
                    "method": method,
                    "inputs": inputs,
                }
            )

        return forms

    def extract_assets(
        self,
        soup: BeautifulSoup,
        base_url: str,
        hostname: str,
    ) -> dict[str, list[str]]:
        assets = {
            "scripts": [],
            "stylesheets": [],
            "images": [],
        }

        for script in soup.find_all(
            "script",
            src=True,
        ):
            url = urljoin(
                base_url,
                str(script.get("src")),
            )

            if self.is_same_host(
                url,
                hostname,
            ):
                assets["scripts"].append(
                    self.normalize_url(url)
                )

        for stylesheet in soup.find_all(
            "link",
            href=True,
        ):
            relation = stylesheet.get(
                "rel",
                [],
            )

            if isinstance(relation, str):
                relation = [relation]

            if "stylesheet" not in [
                str(item).lower()
                for item in relation
            ]:
                continue

            url = urljoin(
                base_url,
                str(stylesheet.get("href")),
            )

            if self.is_same_host(
                url,
                hostname,
            ):
                assets["stylesheets"].append(
                    self.normalize_url(url)
                )

        for image in soup.find_all(
            "img",
            src=True,
        ):
            url = urljoin(
                base_url,
                str(image.get("src")),
            )

            if self.is_same_host(
                url,
                hostname,
            ):
                assets["images"].append(
                    self.normalize_url(url)
                )

        for key in assets:
            assets[key] = unique_items(
                assets[key]
            )

        return assets

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        hostname = target.hostname

        page = self.fetch_page(
            target.url
        )

        if not page.get("success"):
            return {
                "target": hostname,
                "status": "failed",
                "error": page.get("error"),
                "links": [],
                "forms": [],
                "assets": {},
            }

        final_url = str(
            page.get("url")
            or target.url
        )

        html = str(
            page.get("html")
            or ""
        )

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

        links = self.extract_links(
            soup,
            final_url,
        )

        same_host_links = [
            link
            for link in links
            if self.is_same_host(
                link,
                hostname,
            )
        ]

        forms = self.extract_forms(
            soup,
            final_url,
        )

        assets = self.extract_assets(
            soup,
            final_url,
            hostname,
        )

        metadata = {
            "canonical": None,
            "robots": None,
            "sitemap": None,
        }

        canonical = soup.find(
            "link",
            attrs={
                "rel": lambda value: (
                    value
                    and (
                        "canonical"
                        in value
                        if isinstance(value, list)
                        else str(value).lower()
                        == "canonical"
                    )
                )
            },
        )

        if canonical and canonical.get("href"):
            metadata["canonical"] = urljoin(
                final_url,
                str(canonical.get("href")),
            )

        robots = soup.find(
            "meta",
            attrs={
                "name": "robots"
            },
        )

        if robots:
            metadata["robots"] = robots.get(
                "content"
            )

        sitemap_url = urljoin(
            final_url,
            "/sitemap.xml",
        )

        metadata["sitemap"] = sitemap_url

        return {
            "target": hostname,
            "status": "success",
            "status_code": page.get(
                "status_code"
            ),
            "base_url": final_url,
            "links": unique_items(
                same_host_links
            ),
            "link_count": len(
                unique_items(same_host_links)
            ),
            "forms": forms,
            "form_count": len(forms),
            "assets": assets,
            "metadata": metadata,
        }
