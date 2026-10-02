"""
ReconX Terminal Animations
--------------------------

Startup, loading, and scanning animations.

DEV BY LORD MINATO
"""

import time
from collections.abc import Iterable

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.status import Status

from .colors import console


def boot_sequence(
    messages: Iterable[str],
    delay: float = 0.18,
) -> None:
    """
    Display the ReconX startup sequence.

    Args:
        messages: Messages to display during initialization.
        delay: Delay between messages in seconds.
    """

    for message in messages:
        console.print(
            f"[bold blue][ SYSTEM ][/bold blue] {message}"
        )
        time.sleep(delay)


def spinner(
    message: str,
    duration: float = 1.5,
) -> None:
    """
    Display a temporary spinner.

    Args:
        message: Spinner message.
        duration: How long the spinner should run.
    """

    with Status(
        f"[bold cyan]{message}[/bold cyan]",
        spinner="dots",
    ):
        time.sleep(duration)


def progress_bar(
    tasks: list[str],
    delay: float = 0.15,
) -> None:
    """
    Display a progress bar for a list of tasks.

    Args:
        tasks: Names of tasks to process.
        delay: Delay after each task.
    """

    if not tasks:
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        task = progress.add_task(
            "Initializing...",
            total=len(tasks),
        )

        for item in tasks:
            progress.update(
                task,
                description=f"Processing {item}",
            )

            time.sleep(delay)
            progress.advance(task)


def scan_animation(
    target: str,
    duration: float = 1.5,
) -> None:
    """
    Display a short scanning animation.

    This is visual only and performs no network activity.
    """

    with Status(
        f"[bold cyan]Scanning target:[/bold cyan] "
        f"[white]{target}[/white]",
        spinner="dots12",
    ):
        time.sleep(duration)


def success_animation(message: str) -> None:
    """Display a completed operation."""

    console.print(
        f"[bold green]✔[/bold green] {message}"
    )
