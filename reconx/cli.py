"""
ReconX Command Line Interface
-----------------------------

Handles ReconX commands and arguments.

DEV BY LORD MINATO
"""

from __future__ import annotations

import argparse
import sys

from rich.table import Table

from . import __version__
from .banner import show_banner, show_status
from .colors import console, error
from .config import SUPPORTED_MODULES


def create_parser() -> argparse.ArgumentParser:
    """Create the ReconX argument parser."""

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

    # ─────────────────────────────────────────
    # scan
    # ─────────────────────────────────────────

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run reconnaissance against an authorized target.",
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
        help="Confirm that you are authorized to scan the target.",
    )

    scan_parser.add_argument(
        "--output",
        "-o",
        choices=["json", "markdown", "html"],
        default="json",
        help="Report format.",
    )

    # ─────────────────────────────────────────
    # version
    # ─────────────────────────────────────────

    subparsers.add_parser(
        "version",
        help="Show ReconX version.",
    )

    # ─────────────────────────────────────────
    # modules
    # ─────────────────────────────────────────

    subparsers.add_parser(
        "modules",
        help="Show available reconnaissance modules.",
    )

    # ─────────────────────────────────────────
    # help
    # ─────────────────────────────────────────

    subparsers.add_parser(
        "help",
        help="Show ReconX help.",
    )

    return parser


def show_help(parser: argparse.ArgumentParser) -> None:
    """Display the ReconX help screen."""

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
    console.print("[bold cyan]Examples[/bold cyan]")

    examples = [
        "python main.py scan example.com --authorized",
        "python main.py scan example.com --module dns --authorized",
        "python main.py scan example.com --all --authorized",
        "python main.py modules",
        "python main.py version",
    ]

    for example in examples:
        console.print(
            f"  [cyan]$[/cyan] {example}"
        )


def show_version() -> None:
    """Display ReconX version information."""

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
    """Display all available ReconX modules."""

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

    for index, (module_id, description) in enumerate(
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


def run_scan(args: argparse.Namespace) -> None:
    """
    Start a ReconX scan.

    The actual engine will be connected here after the
    core engine and reconnaissance modules are implemented.
    """

    if not args.authorized:
        error(
            "Authorization confirmation required."
        )

        console.print(
            "\n[bold yellow]Use:[/bold yellow]\n"
            f"  python main.py scan {args.target} "
            "--authorized\n"
        )

        return

    from .core.engine import ReconEngine

    engine = ReconEngine(
        target=args.target,
        module=args.module,
        run_all=args.all,
        output_format=args.output,
    )

    engine.run()


def interactive_mode() -> None:
    """Start the interactive ReconX console."""

    show_banner()
    show_status()

    console.print()
    console.print(
        "[bold cyan]ReconX interactive mode[/bold cyan]"
    )

    console.print(
        "[dim]Type 'help' for commands or 'exit' to quit.[/dim]"
    )

    while True:
        try:
            command = console.input(
                "\n[bold cyan]reconx[/bold cyan] [bold white]> [/bold white]"
            ).strip()

        except (KeyboardInterrupt, EOFError):
            console.print()
            break

        if not command:
            continue

        if command.lower() in {
            "exit",
            "quit",
            "q",
        }:
            console.print(
                "[bold cyan]ReconX session closed.[/bold cyan]"
            )
            break

        if command.lower() in {
            "help",
            "?",
        }:
            parser = create_parser()
            show_help(parser)
            continue

        if command.lower() == "version":
            show_version()
            continue

        if command.lower() == "modules":
            show_modules()
            continue

        console.print(
            "[yellow]Unknown command.[/yellow] "
            "Type [cyan]help[/cyan] for available commands."
        )


def main() -> None:
    """Main ReconX CLI entry point."""

    parser = create_parser()

    # No arguments = interactive mode.
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

    elif args.command == "scan":
        run_scan(args)

    else:
        show_help(parser)
