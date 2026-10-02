"""
ReconX Command Line Interface
-----------------------------

Handles ReconX commands, arguments, and report management.

DEV BY LORD MINATO
"""

from __future__ import annotations

import argparse
import sys

from rich.table import Table

from . import __version__
from .banner import show_banner, show_status
from .colors import console, error, info
from .config import SUPPORTED_MODULES
from .reporting import ReportManager


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description=(
            "ReconX - Authorized Security "
            "Reconnaissance Framework"
        ),
        add_help=False,
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        metavar="<command>",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help=(
            "Run reconnaissance against "
            "an authorized target."
        ),
    )

    scan_parser.add_argument(
        "target",
        help="Target hostname or URL.",
    )

    scan_parser.add_argument(
        "--module",
        "-m",
        choices=list(SUPPORTED_MODULES.keys()),
        help="Run a specific reconnaissance module.",
    )

    scan_parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available reconnaissance modules.",
    )

    scan_parser.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "Confirm that you are authorized "
            "to scan the target."
        ),
    )

    scan_parser.add_argument(
        "--output",
        "-o",
        choices=[
            "json",
            "markdown",
            "html",
        ],
        default="json",
        help="Preferred report format.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="View generated ReconX reports.",
    )

    report_parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Show reports for a specific "
            "previously scanned target."
        ),
    )

    subparsers.add_parser(
        "version",
        help="Show ReconX version.",
    )

    subparsers.add_parser(
        "modules",
        help="Show available reconnaissance modules.",
    )

    subparsers.add_parser(
        "help",
        help="Show ReconX help.",
    )

    return parser


def show_help(
    parser: argparse.ArgumentParser,
) -> None:
    console.print()

    console.print(
        "[bold cyan]ReconX Command Center[/bold cyan]"
    )

    console.print(
        "[dim]Authorized Security Reconnaissance Framework[/dim]"
    )

    console.print()

    parser.print_help()

    console.print()

    console.print(
        "[bold cyan]Examples[/bold cyan]"
    )

    examples = [
        "python main.py scan example.com --authorized",
        (
            "python main.py scan example.com "
            "--module dns --authorized"
        ),
        (
            "python main.py scan example.com "
            "--all --authorized"
        ),
        "python main.py report",
        "python main.py report example.com",
        "python main.py modules",
        "python main.py version",
    ]

    for example in examples:
        console.print(
            f"  [cyan]$[/cyan] {example}"
        )

    console.print()


def show_version() -> None:
    console.print()

    console.print(
        f"[bold cyan]ReconX[/bold cyan] "
        f"[white]v{__version__}[/white]"
    )

    console.print(
        "[dim]Authorized Security Reconnaissance Framework[/dim]"
    )

    console.print(
        "[dim]DEV BY LORD MINATO[/dim]"
    )

    console.print()


def show_modules() -> None:
    table = Table(
        title="ReconX Intelligence Modules",
        border_style="cyan",
        header_style="bold cyan",
    )

    table.add_column(
        "ID",
        style="bold white",
        justify="center",
    )

    table.add_column(
        "Module",
        style="bold cyan",
    )

    table.add_column(
        "Purpose",
        style="white",
    )

    for index, (
        module_id,
        description,
    ) in enumerate(
        SUPPORTED_MODULES.items(),
        start=1,
    ):
        table.add_row(
            f"{index:02d}",
            module_id,
            description,
        )

    console.print()
    console.print(table)
    console.print()


def show_reports(
    target: str | None = None,
) -> None:
    manager = ReportManager()

    if target:
        report = manager.find(target)

        if report is None:
            error(
                f"No ReconX report found for: {target}"
            )

            console.print(
                "\n[dim]Use "
                "[cyan]python main.py report[/cyan] "
                "to list available reports.[/dim]\n"
            )

            return

        console.print()

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        console.print(
            "[bold white]RECONX REPORT[/bold white]"
        )

        console.print(
            "[bold cyan]"
            "══════════════════════════════════════════"
            "[/bold cyan]"
        )

        console.print(
            f"[bold cyan]Target:[/bold cyan] "
            f"[white]{report.target}[/white]"
        )

        console.print(
            f"[bold cyan]Directory:[/bold cyan] "
            f"[white]{report.directory}[/white]"
        )

        console.print()

        if report.summary:
            console.print(
                f"[bold green]JSON:[/bold green] "
                f"{report.summary}"
            )

        if report.markdown:
            console.print(
                f"[bold green]Markdown:[/bold green] "
                f"{report.markdown}"
            )

        if report.html:
            console.print(
                f"[bold green]HTML:[/bold green] "
                f"{report.html}"
            )

        console.print()

        return

    reports = manager.discover()

    if not reports:
        info(
            "No ReconX reports have been generated yet."
        )

        console.print(
            "\n[dim]Run a scan first:[/dim]\n"
            "  [cyan]python main.py scan "
            "example.com --authorized[/cyan]\n"
        )

        return

    table = Table(
        title="ReconX Report Archive",
        border_style="cyan",
        header_style="bold cyan",
    )

    table.add_column(
        "#",
        justify="center",
        style="bold white",
    )

    table.add_column(
        "Target",
        style="bold cyan",
    )

    table.add_column(
        "Formats",
        style="white",
    )

    table.add_column(
        "Directory",
        style="dim",
    )

    for index, report in enumerate(
        reports,
        start=1,
    ):
        formats = ", ".join(
            report.available_formats
        )

        table.add_row(
            str(index),
            report.target,
            formats or "none",
            str(report.directory),
        )

    console.print()
    console.print(table)
    console.print()

    latest = manager.latest()

    if latest:
        console.print(
            "[bold cyan]Latest report:[/bold cyan] "
            f"[white]{latest.target}[/white]"
        )

        if latest.html:
            console.print(
                f"[bold green]HTML:[/bold green] "
                f"{latest.html}"
            )

        console.print()


def run_scan(
    args: argparse.Namespace,
) -> None:
    if not args.authorized:
        error(
            "Authorization confirmation required."
        )

        console.print(
            "\n[bold yellow]Use:[/bold yellow]\n"
            f"  python main.py scan "
            f"{args.target} --authorized\n"
        )

        return

    from .core.engine import ReconEngine

    engine = ReconEngine(
        target=args.target,
        module=args.module,
        run_all=args.all,
        output_format=args.output,
        authorized=args.authorized,
    )

    engine.run()


def interactive_mode() -> None:
    show_banner()
    show_status()

    console.print()

    console.print(
        "[bold cyan]ReconX interactive mode[/bold cyan]"
    )

    console.print(
        "[dim]Type 'help' for commands "
        "or 'exit' to quit.[/dim]"
    )

    while True:
        try:
            command = console.input(
                "\n"
                "[bold cyan]reconx[/bold cyan] "
                "[bold white]> [/bold white]"
            ).strip()

        except (
            KeyboardInterrupt,
            EOFError,
        ):
            console.print()
            break

        if not command:
            continue

        lowered = command.lower()

        if lowered in {
            "exit",
            "quit",
            "q",
        }:
            console.print(
                "[bold cyan]"
                "ReconX session closed."
                "[/bold cyan]"
            )
            break

        if lowered in {
            "help",
            "?",
        }:
            parser = create_parser()
            show_help(parser)
            continue

        if lowered == "version":
            show_version()
            continue

        if lowered == "modules":
            show_modules()
            continue

        if lowered == "report":
            show_reports()
            continue

        if lowered.startswith(
            "report "
        ):
            target = command[7:].strip()

            if target:
                show_reports(target)
            else:
                show_reports()

            continue

        console.print(
            "[yellow]Unknown command.[/yellow] "
            "Type [cyan]help[/cyan] for available commands."
        )


def main() -> None:
    parser = create_parser()

    if len(sys.argv) == 1:
        interactive_mode()
        return

    args = parser.parse_args()

    if args.command == "help":
        show_help(parser)

    elif args.command == "version":
        show_version()

    elif args.command == "modules":
        show_modules()

    elif args.command == "report":
        show_reports(
            getattr(
                args,
                "target",
                None,
            )
        )

    elif args.command == "scan":
        run_scan(args)

    else:
        show_help(parser)


if __name__ == "__main__":
    main()
