"""
ReconX Report Manager
---------------------

Discovers, indexes, and manages generated ReconX reports.

DEV BY LORD MINATO
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import REPORT_DIR


@dataclass(slots=True)
class ReportEntry:
    target: str
    directory: Path
    summary: Path | None = None
    markdown: Path | None = None
    html: Path | None = None

    @property
    def available_formats(self) -> list[str]:
        formats: list[str] = []

        if self.summary and self.summary.exists():
            formats.append("json")

        if self.markdown and self.markdown.exists():
            formats.append("markdown")

        if self.html and self.html.exists():
            formats.append("html")

        return formats


class ReportManager:
    """
    Handles generated ReconX report directories.
    """

    def __init__(
        self,
        report_dir: Path | None = None,
    ) -> None:
        self.report_dir = (
            report_dir
            if report_dir is not None
            else REPORT_DIR
        )

    def ensure_directory(self) -> Path:
        self.report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        return self.report_dir

    def discover(self) -> list[ReportEntry]:
        self.ensure_directory()

        reports: list[ReportEntry] = []

        for directory in sorted(
            self.report_dir.iterdir(),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        ):
            if not directory.is_dir():
                continue

            reports.append(
                ReportEntry(
                    target=directory.name,
                    directory=directory,
                    summary=self._existing_file(
                        directory,
                        "summary.json",
                    ),
                    markdown=self._existing_file(
                        directory,
                        "report.md",
                    ),
                    html=self._existing_file(
                        directory,
                        "report.html",
                    ),
                )
            )

        return reports

    @staticmethod
    def _existing_file(
        directory: Path,
        filename: str,
    ) -> Path | None:
        path = directory / filename

        if path.exists() and path.is_file():
            return path

        return None

    def latest(self) -> ReportEntry | None:
        reports = self.discover()

        if not reports:
            return None

        return reports[0]

    def find(
        self,
        target: str,
    ) -> ReportEntry | None:
        target = target.strip().lower()

        for report in self.discover():
            if report.target.lower() == target:
                return report

        return None

    def module_reports(
        self,
        target: str,
    ) -> list[Path]:
        report = self.find(target)

        if report is None:
            return []

        return sorted(
            report.directory.glob(
                "*.json"
            )
        )

    def count(self) -> int:
        return len(
            self.discover()
        )
