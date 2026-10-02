"""
ReconX Terminal Theme
---------------------

Centralized styling and status helpers for the ReconX CLI.

DEV BY LORD MINATO
"""

from rich.console import Console
from rich.style import Style


# Shared console instance
console = Console()


# ─────────────────────────────────────────────
# Core ReconX Styles
# ─────────────────────────────────────────────

CYAN = Style(color="cyan", bold=True)
BLUE = Style(color="blue", bold=True)
WHITE = Style(color="white")
DIM = Style(color="bright_black")
GREEN = Style(color="green", bold=True)
YELLOW = Style(color="yellow", bold=True)
RED = Style(color="red", bold=True)
MAGENTA = Style(color="magenta", bold=True)


# ─────────────────────────────────────────────
# Status Symbols
# ─────────────────────────────────────────────

STATUS_OK = "[bold green]●[/bold green]"
STATUS_WARN = "[bold yellow]●[/bold yellow]"
STATUS_ERROR = "[bold red]●[/bold red]"
STATUS_INFO = "[bold cyan]●[/bold cyan]"


def success(message: str) -> None:
    """Print a successful operation message."""
    console.print(
        f"[bold green][ + ][/bold green] {message}"
    )


def info(message: str) -> None:
    """Print an informational message."""
    console.print(
        f"[bold cyan][ i ][/bold cyan] {message}"
    )


def warning(message: str) -> None:
    """Print a warning message."""
    console.print(
        f"[bold yellow][ ! ][/bold yellow] {message}"
    )


def error(message: str) -> None:
    """Print an error message."""
    console.print(
        f"[bold red][ x ][/bold red] {message}"
    )


def system(message: str) -> None:
    """Print a system status message."""
    console.print(
        f"[bold blue][ SYSTEM ][/bold blue] {message}"
    )


def module(message: str) -> None:
    """Print a reconnaissance module message."""
    console.print(
        f"[bold magenta][ MODULE ][/bold magenta] {message}"
    )
