"""
ReconX Scan Engine
------------------

Central orchestration layer for ReconX reconnaissance modules.

DEV BY LORD MINATO
"""

from __future__ import annotations

import time
from typing import Any

from ..animations import scan_animation
from ..colors import console, error, module, success
from ..config import DEFAULT_MODULES, SUPPORTED_MODULES
from ..utils import format_duration
from .permissions import require_authorization
from .session import ScanSession
from .target import Target


class ReconEngine:
    """
    Central ReconX reconnaissance engine.

    The engine is responsible for:

        1. Validating the target
        2. Checking authorization
        3. Creating a scan session
        4. Selecting modules
        5. Executing modules
        6. Collecting results
        7. Completing the session
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

    # ─────────────────────────────────────────
    # Target
    # ─────────────────────────────────────────

    def prepare_target(self) -> Target:
        """Parse and validate the supplied target."""

        self.target = Target.from_input(
            self.raw_target
        )

        return self.target

    # ─────────────────────────────────────────
    # Module Selection
    # ─────────────────────────────────────────

    def select_modules(self) -> list[str]:
        """
        Determine which reconnaissance modules should run.
        """

        if self.selected_module:
            return [self.selected_module]

        if self.run_all or not self.selected_module:
            return list(DEFAULT_MODULES)

        return []

    # ─────────────────────────────────────────
    # Module Loading
    # ─────────────────────────────────────────

    def load_module(
        self,
        module_name: str,
    ) -> Any:
        """
        Dynamically load a ReconX module.

        Each module will eventually expose a `run()`
        function accepting a Target object.
        """

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

    # ─────────────────────────────────────────
    # Execute Module
    # ─────────────────────────────────────────

    def execute_module(
        self,
        module_name: str,
    ) -> None:
        """Execute one reconnaissance module."""

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
                time.perf_counter() - start_time
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

    # ─────────────────────────────────────────
    # Run
    # ─────────────────────────────────────────

    def run(self) -> ScanSession | None:
        """
        Execute the complete ReconX scan.
        """

        try:
            target = self.prepare_target()

        except ValueError as exc:
            error(
                f"Invalid target: {exc}"
            )
            return None

        # Authorization gate.
        if not require_authorization(
            target.hostname,
            confirmed=self.authorized,
        ):
            return None

        modules = self.select_modules()

        self.session = ScanSession(
            target=target.hostname,
            modules=modules,
            metadata={
                "target_url": target.url,
                "output_format": self.output_format,
                "engine_version": "1.0.0",
            },
        )

        self.session.start()

        console.print()
        console.print(
            "[bold cyan]══════════════════════════════════════════[/bold cyan]"
        )
        console.print(
            f"[bold white]Target:[/bold white] "
            f"[cyan]{target.hostname}[/cyan]"
        )
        console.print(
            f"[bold white]URL:[/bold white] "
            f"[cyan]{target.url}[/cyan]"
        )
        console.print(
            f"[bold white]Modules:[/bold white] "
            f"[cyan]{len(modules)}[/cyan]"
        )
        console.print(
            "[bold cyan]══════════════════════════════════════════[/bold cyan]"
        )

        for module_name in modules:
            self.execute_module(
                module_name
            )

        self.session.complete()

        console.print()
        console.print(
            "[bold green]✔ ReconX scan completed.[/bold green]"
        )

        return self.session
