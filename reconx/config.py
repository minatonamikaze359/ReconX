"""
ReconX Configuration
--------------------

Central configuration for the ReconX framework.

DEV BY LORD MINATO
"""

from pathlib import Path

from . import __version__


# ─────────────────────────────────────────────
# Project Information
# ─────────────────────────────────────────────

APP_NAME = "ReconX"
APP_VERSION = __version__
APP_AUTHOR = "Lord Minato"
APP_DESCRIPTION = "Authorized Security Reconnaissance Framework"


# ─────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_DIR = BASE_DIR / "reconx-report"
LOG_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / ".reconx-cache"


# ─────────────────────────────────────────────
# Network Configuration
# ─────────────────────────────────────────────

DEFAULT_TIMEOUT = 10

MAX_REDIRECTS = 5

USER_AGENT = (
    "ReconX/"
    f"{APP_VERSION} "
    "(Authorized Security Reconnaissance Framework)"
)


# ─────────────────────────────────────────────
# Scan Configuration
# ─────────────────────────────────────────────

DEFAULT_MODULES = [
    "dns",
    "subdomains",
    "certificates",
    "http",
    "technologies",
    "headers",
    "endpoints",
    "exposure",
]


SUPPORTED_MODULES = {
    "dns": "DNS Intelligence",
    "subdomains": "Subdomain Discovery",
    "certificates": "Certificate Intelligence",
    "http": "HTTP Analysis",
    "technologies": "Technology Detection",
    "headers": "Security Headers",
    "endpoints": "Endpoint Discovery",
    "exposure": "Exposure Analysis",
}


# ─────────────────────────────────────────────
# HTTP Configuration
# ─────────────────────────────────────────────

HTTP_METHODS = [
    "GET",
    "HEAD",
]


# ─────────────────────────────────────────────
# Output Configuration
# ─────────────────────────────────────────────

REPORT_FORMATS = [
    "json",
    "markdown",
    "html",
]

DEFAULT_REPORT_FORMAT = "json"


# ─────────────────────────────────────────────
# Safety Configuration
# ─────────────────────────────────────────────

AUTHORIZED_SCAN_REQUIRED = True


# ─────────────────────────────────────────────
# Runtime Helpers
# ─────────────────────────────────────────────

def ensure_directories() -> None:
    """
    Create ReconX runtime directories if they don't exist.
    """

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    CACHE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
