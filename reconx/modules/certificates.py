"""
ReconX Certificate Intelligence
-------------------------------

Collects TLS certificate and HTTPS connection metadata
from an authorized target.

DEV BY LORD MINATO
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..config import DEFAULT_TIMEOUT
from ..core.target import Target


class CertificateModule:
    name = "certificates"
    description = "Certificate Intelligence"

    def __init__(self) -> None:
        self.timeout = DEFAULT_TIMEOUT

    def connect(
        self,
        target: Target,
    ) -> tuple[
        dict[str, Any],
        ssl.SSLSocket,
    ]:
        """
        Establish a normal TLS connection and retrieve
        the peer certificate.

        No exploit or bypass behavior is performed.
        """

        hostname = target.hostname
        port = target.port or 443

        context = ssl.create_default_context()

        raw_socket = socket.create_connection(
            (hostname, port),
            timeout=self.timeout,
        )

        tls_socket = context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        )

        certificate = tls_socket.getpeercert()

        return certificate, tls_socket

    @staticmethod
    def parse_name(
        name: tuple[tuple[tuple[str, str], ...], ...],
    ) -> dict[str, str]:
        result: dict[str, str] = {}

        for section in name:
            for key, value in section:
                result[key] = value

        return result

    @staticmethod
    def parse_san(
        certificate: dict[str, Any],
    ) -> list[str]:
        sans: list[str] = []

        for entry_type, value in certificate.get(
            "subjectAltName",
            (),
        ):
            sans.append(
                f"{entry_type}:{value}"
            )

        return sans

    @staticmethod
    def parse_timestamp(
        value: str | None,
    ) -> str | None:
        if not value:
            return None

        try:
            parsed = datetime.strptime(
                value,
                "%b %d %H:%M:%S %Y %Z",
            )

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

            return parsed.isoformat()

        except ValueError:
            return value

    @staticmethod
    def calculate_validity(
        not_before: str | None,
        not_after: str | None,
    ) -> dict[str, Any]:
        if not not_before or not not_after:
            return {
                "valid": None,
                "days_remaining": None,
            }

        try:
            start = datetime.strptime(
                not_before,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            end = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            return {
                "valid": start <= now <= end,
                "days_remaining": (
                    (end - now).total_seconds()
                    / 86400
                ),
            }

        except ValueError:
            return {
                "valid": None,
                "days_remaining": None,
            }

    def run(
        self,
        target: Target,
    ) -> dict[str, Any]:
        hostname = target.hostname
        port = target.port or 443

        result: dict[str, Any] = {
            "target": hostname,
            "port": port,
            "protocol": "TLS",
            "certificate": {},
            "connection": {},
        }

        tls_socket: ssl.SSLSocket | None = None

        try:
            certificate, tls_socket = self.connect(
                target
            )

            not_before = certificate.get(
                "notBefore"
            )

            not_after = certificate.get(
                "notAfter"
            )

            validity = self.calculate_validity(
                not_before,
                not_after,
            )

            cipher = tls_socket.cipher()

            result["certificate"] = {
                "subject": self.parse_name(
                    certificate.get(
                        "subject",
                        (),
                    )
                ),
                "issuer": self.parse_name(
                    certificate.get(
                        "issuer",
                        (),
                    )
                ),
                "serial_number": certificate.get(
                    "serialNumber"
                ),
                "version": certificate.get(
                    "version"
                ),
                "not_before": self.parse_timestamp(
                    not_before
                ),
                "not_after": self.parse_timestamp(
                    not_after
                ),
                "subject_alt_names": self.parse_san(
                    certificate
                ),
                "validity": validity,
            }

            result["connection"] = {
                "tls_version": tls_socket.version(),
                "cipher": {
                    "name": cipher[0]
                    if cipher
                    else None,
                    "protocol": cipher[1]
                    if cipher
                    else None,
                    "bits": cipher[2]
                    if cipher
                    else None,
                },
            }

            result["status"] = "success"

        except (
            ssl.SSLError,
            socket.timeout,
            socket.gaierror,
            ConnectionError,
            OSError,
        ) as exc:
            result["status"] = "failed"
            result["error"] = str(exc)

        finally:
            if tls_socket is not None:
                try:
                    tls_socket.close()
                except OSError:
                    pass

        return result
