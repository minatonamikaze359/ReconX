"""
ReconX Permission System
------------------------

Handles authorization confirmation before reconnaissance.

DEV BY LORD MINATO
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.panel import Panel

from ..colors import console


@dataclass(slots=True)
class PermissionResult:
    """Result of an authorization check."""

    authorized: bool
    message: str


AUTHORIZATION_MESSAGE = """
ReconX is intended for authorized security testing only.

Only continue if you:
  • Own the target, OR
  • Have explicit permission to assess it.

Unauthorized scanning may violate laws, contracts,
or the target's terms of service.
"""


def display_authorization_notice(target: str) -> None:
    """Display the authorization notice."""

    console.print(
        Panel(
            AUTHORIZATION_MESSAGE.strip(),
            title="[bold yellow]AUTHORIZATION REQUIRED[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    console.print(
        f"\n[bold cyan]Target:[/bold cyan] "
        f"[white]{target}[/white]"
    )


def check_authorization(
    target: str,
    confirmed: bool = False,
) -> PermissionResult:
    """
    Check whether the scan has been explicitly authorized.

    Args:
        target: Target being assessed.
        confirmed: Whether the CLI authorization flag was supplied.

    Returns:
        PermissionResult.
    """

    if confirmed:
        return PermissionResult(
            authorized=True,
            message=(
                "Authorization confirmation received."
            ),
        )

    return PermissionResult(
        authorized=False,
        message=(
            f"Authorization confirmation required "
            f"for target: {target}"
        ),
    )


def require_authorization(
    target: str,
    confirmed: bool = False,
) -> bool:
    """
    Enforce the authorization requirement.

    Returns:
        True when authorization is confirmed.
        False otherwise.
    """

    result = check_authorization(
        target=target,
        confirmed=confirmed,
    )

    if result.authorized:
        return True

    display_authorization_notice(target)

    console.print(
        "\n[bold yellow]Scan blocked.[/bold yellow]"
    )

    console.print(
        "[dim]Re-run with --authorized after confirming "
        "you have permission to assess this target.[/dim]\n"
    )

    return False
