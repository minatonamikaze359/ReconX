"""
ReconX Terminal Banner
----------------------

Handles the startup banner and system information display.

DEV BY LORD MINATO
"""

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__


console = Console()


BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██████╔╝██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██╔══██╗██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
"""


def show_banner() -> None:
    """Display the main ReconX banner."""

    console.clear()

    logo = Text(BANNER)
    logo.stylize("bold cyan")

    title = Text()
    title.append("W E L C O M E   T O   R E C O N X\n", style="bold white")
    title.append("AUTHORIZED SECURITY RECON\n", style="bold cyan")
    title.append("DEV BY LORD MINATO", style="bold blue")

    panel_content = Text()
    panel_content.append_text(logo)
    panel_content.append("\n")
    panel_content.append_text(title)

    panel = Panel(
        Align.center(panel_content),
        border_style="cyan",
        padding=(1, 2),
        title=f"[bold cyan]ReconX v{__version__}[/bold cyan]",
        subtitle="[dim]Authorized Security Testing[/dim]",
    )

    console.print(panel)


def show_status() -> None:
    """Display ReconX initialization status."""

    statuses = [
        ("SYSTEM", "Initializing ReconX Engine...", "yellow"),
        ("SYSTEM", "Loading reconnaissance modules...", "yellow"),
        ("SYSTEM", "Initializing security checks...", "yellow"),
        ("SYSTEM", "Preparing terminal interface...", "yellow"),
        ("SYSTEM", "ReconX Engine ready.", "green"),
    ]

    for category, message, color in statuses:
        console.print(
            f"[bold {color}][ {category} ][/bold {color}] "
            f"{message}"
        )


def show_prompt() -> None:
    """Display the interactive ReconX prompt."""

    console.print()
    console.print(
        "[bold cyan]reconx[/bold cyan] "
        "[bold white]>[/bold white] ",
        end="",
    )
