"""
ReconX Markdown Reporting
-------------------------

Generates a human-readable Markdown report from
a completed ReconX scan session.

DEV BY LORD MINATO
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.session import ScanSession
from ..utils import format_duration, safe_filename


class MarkdownReporter:
    """
    Generates a Markdown security reconnaissance report.
    """

    name = "markdown"

    def __init__(
        self,
        output_dir: Path,
    ) -> None:
        self.output_dir = output_dir

    @staticmethod
    def severity_icon(
        severity: str,
    ) -> str:
        icons = {
            "info": "ℹ️",
            "low": "🟡",
            "medium": "🟠",
            "high": "🔴",
        }

        return icons.get(
            severity.lower(),
            "•",
        )

    def build_module_section(
        self,
        module_name: str,
        data: Any,
    ) -> str:
        lines: list[str] = []

        lines.append(
            f"## {module_name.title()}"
        )
        lines.append("")

        if not isinstance(data, dict):
            lines.append(
                "```text"
            )
            lines.append(
                str(data)
            )
            lines.append(
                "```"
            )
            lines.append("")

            return "\n".join(lines)

        status = data.get(
            "status"
        )

        if status:
            lines.append(
                f"**Status:** `{status}`"
            )
            lines.append("")

        if "error" in data:
            lines.append(
                f"**Error:** `{data['error']}`"
            )
            lines.append("")

        summary = data.get(
            "summary"
        )

        if isinstance(summary, dict):
            lines.append(
                "### Summary"
            )
            lines.append("")

            for key, value in summary.items():
                formatted_key = (
                    str(key)
                    .replace("_", " ")
                    .title()
                )

                lines.append(
                    f"- **{formatted_key}:** "
                    f"`{value}`"
                )

            lines.append("")

        if module_name == "dns":
            self._dns_section(
                lines,
                data,
            )

        elif module_name == "subdomains":
            self._subdomain_section(
                lines,
                data,
            )

        elif module_name == "certificates":
            self._certificate_section(
                lines,
                data,
            )

        elif module_name == "http":
            self._http_section(
                lines,
                data,
            )

        elif module_name == "technologies":
            self._technology_section(
                lines,
                data,
            )

        elif module_name == "headers":
            self._headers_section(
                lines,
                data,
            )

        elif module_name == "endpoints":
            self._endpoint_section(
                lines,
                data,
            )

        elif module_name == "exposure":
            self._exposure_section(
                lines,
                data,
            )

        return "\n".join(lines)

    @staticmethod
    def _dns_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        records = data.get(
            "records",
            {},
        )

        if not records:
            return

        lines.append(
            "### DNS Records"
        )
        lines.append("")

        for record_type, values in records.items():
            lines.append(
                f"#### `{record_type}`"
            )

            if values:
                for value in values:
                    lines.append(
                        f"- `{value}`"
                    )
            else:
                lines.append(
                    "- No records observed."
                )

            lines.append("")

    @staticmethod
    def _subdomain_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        subdomains = data.get(
            "subdomains",
            [],
        )

        lines.append(
            "### Discovered Subdomains"
        )
        lines.append("")

        if not subdomains:
            lines.append(
                "No subdomains were observed."
            )
            lines.append("")
            return

        for subdomain in subdomains:
            lines.append(
                f"- `{subdomain}`"
            )

        lines.append("")

    @staticmethod
    def _certificate_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        certificate = data.get(
            "certificate",
            {},
        )

        connection = data.get(
            "connection",
            {},
        )

        if certificate:
            lines.append(
                "### Certificate"
            )
            lines.append("")

            subject = certificate.get(
                "subject"
            )

            issuer = certificate.get(
                "issuer"
            )

            lines.append(
                f"- **Subject:** `{subject}`"
            )

            lines.append(
                f"- **Issuer:** `{issuer}`"
            )

            lines.append(
                f"- **Serial:** "
                f"`{certificate.get('serial_number')}`"
            )

            lines.append(
                f"- **Valid From:** "
                f"`{certificate.get('not_before')}`"
            )

            lines.append(
                f"- **Valid Until:** "
                f"`{certificate.get('not_after')}`"
            )

            lines.append("")

            sans = certificate.get(
                "subject_alt_names",
                [],
            )

            if sans:
                lines.append(
                    "#### Subject Alternative Names"
                )

                for san in sans:
                    lines.append(
                        f"- `{san}`"
                    )

                lines.append("")

        if connection:
            lines.append(
                "### TLS Connection"
            )
            lines.append("")

            lines.append(
                f"- **TLS Version:** "
                f"`{connection.get('tls_version')}`"
            )

            cipher = connection.get(
                "cipher",
                {},
            )

            if cipher:
                lines.append(
                    f"- **Cipher:** "
                    f"`{cipher.get('name')}`"
                )

                lines.append(
                    f"- **Bits:** "
                    f"`{cipher.get('bits')}`"
                )

            lines.append("")

    @staticmethod
    def _http_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        checks = data.get(
            "checks",
            {},
        )

        if not checks:
            return

        lines.append(
            "### HTTP Checks"
        )
        lines.append("")

        for name, check in checks.items():
            lines.append(
                f"#### {name}"
            )
            lines.append("")

            if not isinstance(check, dict):
                lines.append(
                    f"`{check}`"
                )
                lines.append("")
                continue

            lines.append(
                f"- **Status:** "
                f"`{check.get('status_code')}`"
            )

            lines.append(
                f"- **Final URL:** "
                f"`{check.get('final_url')}`"
            )

            lines.append(
                f"- **Content Type:** "
                f"`{check.get('content_type')}`"
            )

            lines.append(
                f"- **Server:** "
                f"`{check.get('server')}`"
            )

            lines.append(
                f"- **Redirects:** "
                f"`{check.get('redirect_count', 0)}`"
            )

            lines.append("")

    @staticmethod
    def _technology_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        technologies = data.get(
            "technologies",
            [],
        )

        lines.append(
            "### Detected Technologies"
        )
        lines.append("")

        if not technologies:
            lines.append(
                "No technology indicators were observed."
            )
            lines.append("")
            return

        for item in technologies:
            technology = item.get(
                "technology",
                "Unknown",
            )

            category = item.get(
                "category",
                "Unknown",
            )

            source = item.get(
                "source",
                "Unknown",
            )

            lines.append(
                f"- **{technology}** "
                f"({category}) — `{source}`"
            )

        lines.append("")

    @staticmethod
    def _headers_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        analysis = data.get(
            "analysis",
            {},
        )

        findings = analysis.get(
            "findings",
            [],
        )

        if not findings:
            return

        lines.append(
            "### Security Header Analysis"
        )
        lines.append("")

        for finding in findings:
            header = finding.get(
                "header",
                "Unknown",
            )

            present = finding.get(
                "present",
                False,
            )

            icon = (
                "✅"
                if present
                else "⚠️"
            )

            lines.append(
                f"- {icon} **{header}**"
            )

            if present:
                lines.append(
                    f"  - Value: "
                    f"`{finding.get('value')}`"
                )
            else:
                lines.append(
                    "  - Not observed"
                )

        lines.append("")

    @staticmethod
    def _endpoint_section(
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        links = data.get(
            "links",
            [],
        )

        forms = data.get(
            "forms",
            [],
        )

        lines.append(
            "### Discovered Links"
        )
        lines.append("")

        if links:
            for link in links:
                lines.append(
                    f"- `{link}`"
                )
        else:
            lines.append(
                "No same-host links observed."
            )

        lines.append("")

        lines.append(
            "### Forms"
        )
        lines.append("")

        if forms:
            for form in forms:
                lines.append(
                    f"- **{form.get('method', 'GET')}** "
                    f"`{form.get('action')}`"
                )
        else:
            lines.append(
                "No forms observed."
            )

        lines.append("")

    def _exposure_section(
        self,
        lines: list[str],
        data: dict[str, Any],
    ) -> None:
        findings = data.get(
            "findings",
            [],
        )

        lines.append(
            "### Exposure Findings"
        )
        lines.append("")

        if not findings:
            lines.append(
                "No observable exposure findings."
            )
            lines.append("")
            return

        for finding in findings:
            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            )

            icon = self.severity_icon(
                severity
            )

            description = finding.get(
                "description",
                "",
            )

            lines.append(
                f"- {icon} **{severity.upper()}** — "
                f"{description}"
            )

            if finding.get("path"):
                lines.append(
                    f"  - Path: "
                    f"`{finding['path']}`"
                )

            if finding.get("header"):
                lines.append(
                    f"  - Header: "
                    f"`{finding['header']}`"
                )

        lines.append("")

    def build(
        self,
        session: ScanSession,
    ) -> str:
        lines: list[str] = []

        lines.append(
            "# ReconX Security Reconnaissance Report"
        )
        lines.append("")

        lines.append(
            "> **DEV BY LORD MINATO**"
        )
        lines.append("")

        lines.append(
            "## Target"
        )
        lines.append("")

        lines.append(
            f"- **Target:** `{session.target}`"
        )

        lines.append(
            f"- **Status:** `{session.status}`"
        )

        lines.append(
            f"- **Started:** "
            f"`{session.started_at.isoformat()}`"
        )

        if session.finished_at:
            lines.append(
                f"- **Finished:** "
                f"`{session.finished_at.isoformat()}`"
            )

        if session.duration_seconds is not None:
            lines.append(
                f"- **Duration:** "
                f"`{format_duration(session.duration_seconds)}`"
            )

        lines.append("")

        lines.append(
            "## Modules"
        )
        lines.append("")

        for module in session.modules:
            status = (
                "completed"
                if module in session.results
                else "failed"
            )

            lines.append(
                f"- `{module}` — {status}"
            )

        lines.append("")

        if session.errors:
            lines.append(
                "## Errors"
            )
            lines.append("")

            for error in session.errors:
                lines.append(
                    f"- **{error.get('module')}**: "
                    f"{error.get('message')}"
                )

            lines.append("")

        lines.append(
            "---"
        )
        lines.append("")

        for module_name, data in (
            session.results.items()
        ):
            lines.append(
                self.build_module_section(
                    module_name,
                    data,
                )
            )

            lines.append(
                "\n---\n"
            )

        lines.append(
            "## ReconX"
        )
        lines.append("")

        lines.append(
            "Generated by the ReconX Authorized "
            "Security Reconnaissance Framework."
        )

        lines.append("")

        return "\n".join(lines)

    def generate(
        self,
        session: ScanSession,
    ) -> Path:
        target_directory = (
            self.output_dir
            / safe_filename(session.target)
        )

        target_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        report_path = (
            target_directory
            / "report.md"
        )

        content = self.build(
            session
        )

        report_path.write_text(
            content,
            encoding="utf-8",
        )

        return report_path
