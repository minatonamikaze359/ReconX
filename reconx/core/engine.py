"""
ReconX Scan Engine
------------------

Central orchestration layer for ReconX reconnaissance
modules and report generation.

DEV BY LORD MINATO
"""

from __future__ import annotations

import time
from typing import Any

from ..animations import scan_animation
from ..colors import console, error, module, success
from ..config import (
    DEFAULT_MODULES,
    REPORT_DIR,
    SUPPORTED_MODULES,
    ensure_directories,
)
from ..reporting import (
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
)
from ..utils import format_duration
from .permissions import require_authorization
from .session import ScanSession
from .target import Target


class ReconEngine:
    """
    Central ReconX reconnaissance engine.

    Responsibilities:
        1. Validate target
        2. Check authorization
        3. Create scan session
        4. Select modules
        5. Execute modules
        6. Collect results
        7. Generate reports
        8. Complete session
    """

    def __init__(
        self,
        target: str,
        module: str | None = None,
        run_all: bool = False,
        output_format: str = "json",
        authorized: bool = False,
    ) -> None:

        self.raw_target = target
        self.selected_module = module
        self.run_all = run_all
        self.output_format = output_format
        self.authorized = authorized

        self.target: Target | None = None
        self.session: ScanSession | None = None

    def prepare_target(self) -> Target:
        self.target = Target.from_input(
            self.raw_target
        )

        return self.target

    def select_modules(self) -> list[str]:
        if self.selected_module:
            return [self.selected_module]

        return list(DEFAULT_MODULES)

    def load_module(
        self,
        module_name: str,
    ) -> Any:
        module_map = {
            "dns": (
                "reconx.modules.dns",
                "DNSModule",
            ),
            "subdomains": (
                "reconx.modules.subdomains",
                "SubdomainModule",
            ),
            "certificates": (
                "reconx.modules.certificates",
                "CertificateModule",
            ),
            "http": (
                "reconx.modules.http",
                "HTTPModule",
            ),
            "technologies": (
                "reconx.modules.technologies",
                "TechnologyModule",
            ),
            "headers": (
                "reconx.modules.headers",
                "HeadersModule",
            ),
            "endpoints": (
                "reconx.modules.endpoints",
                "EndpointModule",
            ),
            "exposure": (
                "reconx.modules.exposure",
                "ExposureModule",
            ),
        }

        if module_name not in module_map:
            raise ValueError(
                f"Unknown ReconX module: {module_name}"
            )

        module_path, class_name = module_map[
            module_name
        ]

        module_object = __import__(
            module_path,
            fromlist=[class_name],
        )

        module_class = getattr(
            module_object,
            class_name,
        )

        return module_class()

    def execute_module(
        self,
        module_name: str,
    ) -> None:
        if self.target is None:
            raise RuntimeError(
                "Target has not been prepared."
            )

        if self.session is None:
            raise RuntimeError(
                "Scan session has not been created."
            )

        description = SUPPORTED_MODULES.get(
            module_name,
            module_name,
        )

        module(
            f"{description} [{module_name}]"
        )

        start_time = time.perf_counter()

        try:
            scan_animation(
                self.target.hostname,
                duration=0.6,
            )

            scanner = self.load_module(
                module_name
            )

            result = scanner.run(
                self.target
            )

            self.session.add_result(
                module_name,
                result,
            )

            elapsed = (
                time.perf_counter()
                - start_time
            )

            success(
                f"{module_name} completed "
                f"({format_duration(elapsed)})"
            )

        except Exception as exc:
            self.session.add_error(
                module=module_name,
                message=str(exc),
            )

            error(
                f"{module_name} failed: {exc}"
            )

    def generate_reports(self) -> dict[str, Any]:
        if self.session is None:
            raise RuntimeError(
                "Cannot generate reports without "
                "a scan session."
            )

        ensure_directories()

        reports: dict[str, Any] = {}

        # JSON report
        json_reporter = JSONReporter(
            output_dir=REPORT_DIR
        )

        reports["json"] = (
            json_reporter.generate(
                self.session
            )
        )

        # Markdown report
        markdown_reporter = MarkdownReporter(
            output_dir=REPORT_DIR
        )

        markdown_path = (
            markdown_reporter.generate(
                self.session
            )
        )

        reports["markdown"] = str(
            markdown_path
        )

        # HTML report
        html_reporter = HTMLReporter(
            output_dir=REPORT_DIR
        )

        html_path = (
            html_reporter.generate(
                self.session
            )
        )

        reports["html"] = str(
            html_path
        )

        return reports

    def show_report_summary(
        self,
        reports: dict[str, Any],
    ) -> None:
        console.print()

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        console.print(
            "[bold white]REPORTS GENERATED[/bold white]"
        )

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        json_report = reports.get(
            "json",
            {},
        )

        if isinstance(json_report, dict):
            directory = json_report.get(
                "directory"
            )

            if directory:
                console.print(
                    f"[bold cyan]Directory:[/bold cyan] "
                    f"[white]{directory}[/white]"
                )

        markdown = reports.get(
            "markdown"
        )

        if markdown:
            console.print(
                f"[bold cyan]Markdown:[/bold cyan] "
                f"[white]{markdown}[/white]"
            )

        html_report = reports.get(
            "html"
        )

        if html_report:
            console.print(
                f"[bold cyan]HTML:[/bold cyan] "
                f"[white]{html_report}[/white]"
            )

        console.print()

    def run(
        self,
    ) -> ScanSession | None:
        try:
            target = self.prepare_target()

        except ValueError as exc:
            error(
                f"Invalid target: {exc}"
            )

            return None

        if not require_authorization(
            target.hostname,
            confirmed=self.authorized,
        ):
            return None

        modules = self.select_modules()

        ensure_directories()

        self.session = ScanSession(
            target=target.hostname,
            modules=modules,
            metadata={
                "target_url": target.url,
                "output_format": (
                    self.output_format
                ),
                "engine_version": "1.0.0",
            },
        )

        self.session.start()

        console.print()

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        console.print(
            "[bold white]TARGET:[/bold white] "
            f"[cyan]{target.hostname}[/cyan]"
        )

        console.print(
            "[bold white]URL:[/bold white] "
            f"[cyan]{target.url}[/cyan]"
        )

        console.print(
            "[bold white]MODULES:[/bold white] "
            f"[cyan]{len(modules)}[/cyan]"
        )

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        for module_name in modules:
            self.execute_module(
                module_name
            )

        self.session.complete()

        console.print()

        console.print(
            "[bold green]"
            "✔ ReconX scan completed."
            "[/bold green]"
        )

        try:
            reports = self.generate_reports()

            self.show_report_summary(
                reports
            )

        except Exception as exc:
            self.session.add_error(
                module="reporting",
                message=str(exc),
            )

            error(
                f"Report generation failed: {exc}"
            )

        return self.session
