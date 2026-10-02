"""
ReconX JSON Reporting
---------------------

Exports ReconX scan sessions into structured JSON reports.

DEV BY LORD MINATO
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import REPORT_DIR
from ..core.session import ScanSession
from ..utils import safe_filename


class JSONReporter:
    """
    Generates machine-readable JSON reports.

    Output structure:

        reconx-report/
        └── target/
            ├── summary.json
            ├── dns.json
            ├── subdomains.json
            ├── certificates.json
            ├── http.json
            ├── technologies.json
            ├── headers.json
            ├── endpoints.json
            └── exposure.json
    """

    name = "json"

    def __init__(
        self,
        output_dir: Path | None = None,
    ) -> None:
        self.output_dir = (
            output_dir
            if output_dir is not None
            else REPORT_DIR
        )

    def get_target_directory(
        self,
        session: ScanSession,
    ) -> Path:
        target_name = safe_filename(
            session.target
        )

        directory = (
            self.output_dir / target_name
        )

        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        return directory

    @staticmethod
    def write_json(
        path: Path,
        data: Any,
    ) -> None:
        with path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False,
                default=str,
            )

    def write_summary(
        self,
        session: ScanSession,
        directory: Path,
    ) -> Path:
        path = directory / "summary.json"

        summary = {
            "target": session.target,
            "status": session.status,
            "modules": session.modules,
            "started_at": session.started_at.isoformat(),
            "finished_at": (
                session.finished_at.isoformat()
                if session.finished_at
                else None
            ),
            "duration_seconds": (
                session.duration_seconds
            ),
            "successful_modules": (
                session.successful_modules
            ),
            "error_count": len(
                session.errors
            ),
            "errors": session.errors,
            "metadata": session.metadata,
        }

        self.write_json(
            path,
            summary,
        )

        return path

    def write_modules(
        self,
        session: ScanSession,
        directory: Path,
    ) -> list[Path]:
        paths: list[Path] = []

        for module_name, result in (
            session.results.items()
        ):
            filename = (
                f"{safe_filename(module_name)}.json"
            )

            path = directory / filename

            self.write_json(
                path,
                result,
            )

            paths.append(path)

        return paths

    def generate(
        self,
        session: ScanSession,
    ) -> dict[str, Any]:
        directory = self.get_target_directory(
            session
        )

        summary_path = self.write_summary(
            session,
            directory,
        )

        module_paths = self.write_modules(
            session,
            directory,
        )

        return {
            "format": self.name,
            "directory": str(directory),
            "summary": str(summary_path),
            "modules": [
                str(path)
                for path in module_paths
            ],
        }
