"""
ReconX HTML Reporting
---------------------

Generates a standalone dark-themed HTML report with
ReconX's terminal-inspired visual identity.

DEV BY LORD MINATO
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..core.session import ScanSession
from ..utils import format_duration, safe_filename


class HTMLReporter:
    """
    Generates a standalone HTML reconnaissance report.
    """

    name = "html"

    def __init__(
        self,
        output_dir: Path,
    ) -> None:
        self.output_dir = output_dir

    @staticmethod
    def escape(
        value: Any,
    ) -> str:
        return html.escape(
            str(value)
        )

    @staticmethod
    def severity_class(
        severity: str,
    ) -> str:
        severity = severity.lower()

        if severity in {
            "high",
            "medium",
            "low",
            "info",
        }:
            return severity

        return "info"

    def render_stat(
        self,
        label: str,
        value: Any,
    ) -> str:
        return f"""
        <div class="stat">
            <div class="stat-value">
                {self.escape(value)}
            </div>
            <div class="stat-label">
                {self.escape(label)}
            </div>
        </div>
        """

    def render_code(
        self,
        value: Any,
    ) -> str:
        return (
            "<code>"
            + self.escape(value)
            + "</code>"
        )

    def render_dns(
        self,
        data: dict[str, Any],
    ) -> str:
        records = data.get(
            "records",
            {},
        )

        cards: list[str] = []

        for record_type, values in records.items():
            values_html = ""

            if values:
                for value in values:
                    values_html += (
                        f"<li>{self.render_code(value)}</li>"
                    )
            else:
                values_html = (
                    '<li class="muted">'
                    "No records observed."
                    "</li>"
                )

            cards.append(
                f"""
                <div class="mini-card">
                    <div class="mini-title">
                        {self.escape(record_type)}
                    </div>
                    <ul>
                        {values_html}
                    </ul>
                </div>
                """
            )

        return "".join(cards)

    def render_subdomains(
        self,
        data: dict[str, Any],
    ) -> str:
        subdomains = data.get(
            "subdomains",
            [],
        )

        if not subdomains:
            return (
                '<div class="empty">'
                "No subdomains observed."
                "</div>"
            )

        return (
            '<div class="tag-grid">'
            + "".join(
                f'<span class="tag">'
                f'{self.escape(item)}'
                f"</span>"
                for item in subdomains
            )
            + "</div>"
        )

    def render_certificate(
        self,
        data: dict[str, Any],
    ) -> str:
        certificate = data.get(
            "certificate",
            {},
        )

        connection = data.get(
            "connection",
            {},
        )

        if not certificate:
            return (
                '<div class="empty">'
                "Certificate information unavailable."
                "</div>"
            )

        subject = certificate.get(
            "subject",
            {},
        )

        issuer = certificate.get(
            "issuer",
            {},
        )

        validity = certificate.get(
            "validity",
            {},
        )

        sans = certificate.get(
            "subject_alt_names",
            [],
        )

        cipher = connection.get(
            "cipher",
            {},
        )

        fields = [
            (
                "Subject",
                subject,
            ),
            (
                "Issuer",
                issuer,
            ),
            (
                "Serial Number",
                certificate.get(
                    "serial_number"
                ),
            ),
            (
                "Valid From",
                certificate.get(
                    "not_before"
                ),
            ),
            (
                "Valid Until",
                certificate.get(
                    "not_after"
                ),
            ),
            (
                "Validity",
                validity.get(
                    "valid"
                ),
            ),
            (
                "Days Remaining",
                round(
                    validity.get(
                        "days_remaining"
                    ) or 0,
                    2,
                ),
            ),
            (
                "TLS Version",
                connection.get(
                    "tls_version"
                ),
            ),
            (
                "Cipher",
                cipher.get(
                    "name"
                ),
            ),
        ]

        rows = ""

        for label, value in fields:
            rows += f"""
            <div class="detail-row">
                <span>{self.escape(label)}</span>
                <strong>{self.escape(value)}</strong>
            </div>
            """

        san_html = ""

        if sans:
            san_html = (
                '<div class="tag-grid">'
                + "".join(
                    f'<span class="tag">'
                    f'{self.escape(san)}'
                    f"</span>"
                    for san in sans
                )
                + "</div>"
            )
        else:
            san_html = (
                '<div class="muted">'
                "No SAN entries observed."
                "</div>"
            )

        return f"""
        <div class="detail-list">
            {rows}
        </div>

        <h4>Subject Alternative Names</h4>

        {san_html}
        """

    def render_http(
        self,
        data: dict[str, Any],
    ) -> str:
        checks = data.get(
            "checks",
            {},
        )

        cards: list[str] = []

        for name, check in checks.items():
            if not isinstance(check, dict):
                continue

            status_code = check.get(
                "status_code",
                "N/A",
            )

            cards.append(
                f"""
                <div class="mini-card">
                    <div class="mini-title">
                        {self.escape(name)}
                    </div>

                    <div class="detail-row">
                        <span>Status</span>
                        <strong>
                            {self.escape(status_code)}
                        </strong>
                    </div>

                    <div class="detail-row">
                        <span>Final URL</span>
                        <strong>
                            {self.escape(
                                check.get("final_url")
                            )}
                        </strong>
                    </div>

                    <div class="detail-row">
                        <span>Content Type</span>
                        <strong>
                            {self.escape(
                                check.get("content_type")
                            )}
                        </strong>
                    </div>

                    <div class="detail-row">
                        <span>Server</span>
                        <strong>
                            {self.escape(
                                check.get("server")
                            )}
                        </strong>
                    </div>

                    <div class="detail-row">
                        <span>Redirects</span>
                        <strong>
                            {self.escape(
                                check.get(
                                    "redirect_count",
                                    0,
                                )
                            )}
                        </strong>
                    </div>
                </div>
                """
            )

        return "".join(cards)

    def render_technologies(
        self,
        data: dict[str, Any],
    ) -> str:
        technologies = data.get(
            "technologies",
            [],
        )

        if not technologies:
            return (
                '<div class="empty">'
                "No technology indicators observed."
                "</div>"
            )

        cards: list[str] = []

        for item in technologies:
            cards.append(
                f"""
                <div class="tech-card">
                    <div class="tech-name">
                        {self.escape(
                            item.get(
                                "technology",
                                "Unknown",
                            )
                        )}
                    </div>

                    <div class="tech-category">
                        {self.escape(
                            item.get(
                                "category",
                                "Unknown",
                            )
                        )}
                    </div>

                    <div class="tech-source">
                        Source:
                        {self.escape(
                            item.get(
                                "source",
                                "Unknown",
                            )
                        )}
                    </div>
                </div>
                """
            )

        return (
            '<div class="tech-grid">'
            + "".join(cards)
            + "</div>"
        )

    def render_headers(
        self,
        data: dict[str, Any],
    ) -> str:
        analysis = data.get(
            "analysis",
            {},
        )

        findings = analysis.get(
            "findings",
            [],
        )

        rows: list[str] = []

        for finding in findings:
            present = finding.get(
                "present",
                False,
            )

            state = (
                '<span class="badge ok">'
                "PRESENT"
                "</span>"
                if present
                else
                '<span class="badge warn">'
                "NOT OBSERVED"
                "</span>"
            )

            value = (
                finding.get(
                    "value"
                )
                if present
                else "—"
            )

            rows.append(
                f"""
                <tr>
                    <td>
                        {self.escape(
                            finding.get(
                                "header",
                                "Unknown",
                            )
                        )}
                    </td>
                    <td>{state}</td>
                    <td>
                        {self.escape(value)}
                    </td>
                </tr>
                """
            )

        return f"""
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                        <th>Value</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>
        """

    def render_endpoints(
        self,
        data: dict[str, Any],
    ) -> str:
        links = data.get(
            "links",
            [],
        )

        forms = data.get(
            "forms",
            [],
        )

        links_html = "".join(
            f"<li>{self.render_code(link)}</li>"
            for link in links
        )

        forms_html = ""

        for form in forms:
            forms_html += f"""
            <div class="mini-card">
                <div class="mini-title">
                    {self.escape(
                        form.get(
                            "method",
                            "GET",
                        )
                    )}
                    &nbsp;
                    {self.escape(
                        form.get(
                            "action",
                            "",
                        )
                    )}
                </div>
            </div>
            """

        if not links:
            links_html = (
                '<li class="muted">'
                "No same-host links observed."
                "</li>"
            )

        if not forms_html:
            forms_html = (
                '<div class="empty">'
                "No forms observed."
                "</div>"
            )

        return f"""
        <h4>Same-Host Links</h4>

        <ul class="endpoint-list">
            {links_html}
        </ul>

        <h4>Forms</h4>

        <div class="card-grid">
            {forms_html}
        </div>
        """

    def render_exposure(
        self,
        data: dict[str, Any],
    ) -> str:
        findings = data.get(
            "findings",
            [],
        )

        if not findings:
            return (
                '<div class="empty success-box">'
                "No observable exposure findings."
                "</div>"
            )

        cards: list[str] = []

        for finding in findings:
            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            )

            css_class = self.severity_class(
                severity
            )

            cards.append(
                f"""
                <div class="finding {css_class}">
                    <div class="finding-header">
                        <span class="badge {css_class}">
                            {self.escape(
                                severity.upper()
                            )}
                        </span>

                        <strong>
                            {self.escape(
                                finding.get(
                                    "type",
                                    "Observation",
                                )
                            )}
                        </strong>
                    </div>

                    <p>
                        {self.escape(
                            finding.get(
                                "description",
                                "",
                            )
                        )}
                    </p>

                    {
                        (
                            f'<div class="finding-meta">'
                            f'Path: '
                            f'<code>'
                            f'{self.escape(finding["path"])}'
                            f'</code>'
                            f'</div>'
                        )
                        if finding.get("path")
                        else ""
                    }

                    {
                        (
                            f'<div class="finding-meta">'
                            f'Header: '
                            f'<code>'
                            f'{self.escape(finding["header"])}'
                            f'</code>'
                            f'</div>'
                        )
                        if finding.get("header")
                        else ""
                    }
                </div>
                """
            )

        return "".join(cards)

    def render_module(
        self,
        module_name: str,
        data: Any,
    ) -> str:
        renderer_map = {
            "dns": self.render_dns,
            "subdomains": self.render_subdomains,
            "certificates": self.render_certificate,
            "http": self.render_http,
            "technologies": self.render_technologies,
            "headers": self.render_headers,
            "endpoints": self.render_endpoints,
            "exposure": self.render_exposure,
        }

        renderer = renderer_map.get(
            module_name
        )

        if renderer is None:
            return (
                "<pre>"
                + self.escape(
                    json.dumps(
                        data,
                        indent=2,
                        default=str,
                    )
                )
                + "</pre>"
            )

        return renderer(data)

    def build(
        self,
        session: ScanSession,
    ) -> str:
        duration = (
            format_duration(
                session.duration_seconds
            )
            if session.duration_seconds is not None
            else "N/A"
        )

        stats = f"""
        <div class="stats">
            {self.render_stat(
                "Modules",
                len(session.modules),
            )}

            {self.render_stat(
                "Completed",
                len(session.results),
            )}

            {self.render_stat(
                "Errors",
                len(session.errors),
            )}

            {self.render_stat(
                "Duration",
                duration,
            )}
        </div>
        """

        modules_html = ""

        for module_name, data in (
            session.results.items()
        ):
            module_title = (
                module_name
                .replace("_", " ")
                .title()
            )

            modules_html += f"""
            <section class="module">
                <div class="module-header">
                    <div>
                        <span class="module-index">
                            MODULE
                        </span>

                        <h2>
                            {self.escape(
                                module_title
                            )}
                        </h2>
                    </div>

                    <span class="badge ok">
                        COMPLETE
                    </span>
                </div>

                <div class="module-body">
                    {self.render_module(
                        module_name,
                        data,
                    )}
                </div>
            </section>
            """

        errors_html = ""

        if session.errors:
            errors_html = """
            <section class="module">
                <div class="module-header">
                    <div>
                        <span class="module-index">
                            SYSTEM
                        </span>

                        <h2>Scan Errors</h2>
                    </div>

                    <span class="badge high">
                        REVIEW
                    </span>
                </div>

                <div class="module-body">
            """

            for error_item in session.errors:
                errors_html += f"""
                    <div class="finding medium">
                        <strong>
                            {self.escape(
                                error_item.get(
                                    "module",
                                    "engine",
                                )
                            )}
                        </strong>

                        <p>
                            {self.escape(
                                error_item.get(
                                    "message",
                                    "",
                                )
                            )}
                        </p>
                    </div>
                """

            errors_html += """
                </div>
            </section>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
ReconX Report — {self.escape(session.target)}
</title>

<style>
:root {{
    --bg: #05070a;
    --panel: #0a0f14;
    --panel-2: #0d141b;
    --border: #12303d;
    --cyan: #00e5ff;
    --cyan-soft: #66f2ff;
    --text: #e7faff;
    --muted: #78909c;
    --green: #39ff88;
    --yellow: #ffd166;
    --orange: #ff9f43;
    --red: #ff4d6d;
}}

* {{
    box-sizing: border-box;
}}

html {{
    scroll-behavior: smooth;
}}

body {{
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            rgba(0, 229, 255, .08),
            transparent 30%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(0, 100, 255, .06),
            transparent 35%
        ),
        var(--bg);
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    line-height: 1.6;
}}

body::before {{
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .035;
    background-image:
        linear-gradient(
            rgba(255,255,255,.5) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.5) 1px,
            transparent 1px
        );
    background-size: 40px 40px;
}}

.container {{
    width: min(1180px, calc(100% - 32px));
    margin: auto;
}}

.hero {{
    padding: 70px 0 35px;
}}

.brand {{
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: var(--cyan);
    font-weight: 800;
    letter-spacing: .22em;
    font-size: 13px;
}}

.brand-dot {{
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--cyan);
    box-shadow:
        0 0 10px var(--cyan),
        0 0 25px var(--cyan);
}}

h1 {{
    margin: 18px 0 8px;
    font-size: clamp(38px, 7vw, 76px);
    line-height: .98;
    letter-spacing: -.045em;
}}

.hero p {{
    color: var(--muted);
    max-width: 720px;
}}

.target {{
    display: inline-flex;
    padding: 10px 15px;
    margin-top: 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: rgba(10,15,20,.8);
    color: var(--cyan-soft);
    font-family: monospace;
}}

.stats {{
    display: grid;
    grid-template-columns:
        repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin: 24px 0 35px;
}}

.stat {{
    background: linear-gradient(
        145deg,
        var(--panel),
        var(--panel-2)
    );
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
}}

.stat-value {{
    color: var(--cyan);
    font-size: 27px;
    font-weight: 800;
}}

.stat-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .12em;
}}

.module {{
    margin: 18px 0;
    background: rgba(10,15,20,.88);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    box-shadow:
        0 15px 50px rgba(0,0,0,.2);
}}

.module-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
    background: rgba(13,20,27,.75);
}}

.module-index {{
    color: var(--cyan);
    font-size: 10px;
    font-weight: 800;
    letter-spacing: .18em;
}}

.module h2 {{
    margin: 3px 0 0;
    font-size: 23px;
}}

.module-body {{
    padding: 24px;
}}

.card-grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(240px, 1fr));
    gap: 12px;
}}

.mini-card,
.tech-card {{
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
}}

.mini-title {{
    color: var(--cyan);
    font-weight: 800;
    margin-bottom: 8px;
}}

.tech-grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(210px, 1fr));
    gap: 12px;
}}

.tech-name {{
    font-weight: 800;
    color: var(--cyan-soft);
}}

.tech-category {{
    color: var(--text);
    font-size: 13px;
    margin-top: 5px;
}}

.tech-source {{
    color: var(--muted);
    font-size: 11px;
    margin-top: 10px;
}}

.detail-list {{
    display: grid;
    gap: 1px;
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
}}

.detail-row {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    padding: 12px 14px;
    background: var(--panel-2);
    border-bottom: 1px solid var(--border);
}}

.detail-row:last-child {{
    border-bottom: 0;
}}

.detail-row span {{
    color: var(--muted);
}}

.detail-row strong {{
    color: var(--text);
    text-align: right;
    overflow-wrap: anywhere;
}}

.tag-grid {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}

.tag {{
    display: inline-flex;
    padding: 6px 9px;
    border: 1px solid var(--border);
    border-radius: 7px;
    background: #081018;
    color: var(--cyan-soft);
    font-family: monospace;
    font-size: 12px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    padding: 12px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
}}

th {{
    color: var(--cyan);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

td {{
    color: var(--text);
    font-size: 13px;
}}

.table-wrap {{
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 10px;
}}

.endpoint-list {{
    padding-left: 20px;
}}

.endpoint-list li {{
    margin: 6px 0;
}}

code {{
    color: var(--cyan-soft);
    font-family: "Cascadia Code", monospace;
    overflow-wrap: anywhere;
}}

.badge {{
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 4px 9px;
    font-size: 10px;
    font-weight: 900;
    letter-spacing: .08em;
}}

.badge.ok {{
    color: var(--green);
    background: rgba(57,255,136,.08);
    border: 1px solid rgba(57,255,136,.25);
}}

.badge.warn,
.finding.low {{
    color: var(--yellow);
}}

.badge.medium,
.finding.medium {{
    color: var(--orange);
}}

.badge.high,
.finding.high {{
    color: var(--red);
}}

.badge.info,
.finding.info {{
    color: var(--cyan);
}}

.finding {{
    padding: 16px;
    margin-bottom: 10px;
    border: 1px solid var(--border);
    border-left: 3px solid currentColor;
    border-radius: 9px;
    background: var(--panel-2);
}}

.finding:last-child {{
    margin-bottom: 0;
}}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 10px;
}}

.finding p {{
    margin: 10px 0 5px;
}}

.finding-meta {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 5px;
}}

.empty {{
    padding: 22px;
    border: 1px dashed var(--border);
    border-radius: 10px;
    color: var(--muted);
    text-align: center;
}}

.success-box {{
    color: var(--green);
}}

.muted {{
    color: var(--muted);
}}

h4 {{
    color: var(--cyan);
    margin: 22px 0 10px;
}}

footer {{
    padding: 45px 0 60px;
    color: var(--muted);
    text-align: center;
    font-size: 12px;
}}

footer strong {{
    color: var(--cyan);
}}

@media (max-width: 700px) {{
    .stats {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .module-header {{
        align-items: flex-start;
        flex-direction: column;
    }}

    .detail-row {{
        flex-direction: column;
        gap: 4px;
    }}

    .detail-row strong {{
        text-align: left;
    }}
}}

@media (max-width: 440px) {{
    .stats {{
        grid-template-columns: 1fr;
    }}

    .container {{
        width: min(
            100% - 20px,
            1180px
        );
    }}

    .module-body,
    .module-header {{
        padding: 17px;
    }}
}}
</style>
</head>

<body>

<div class="container">

<header class="hero">

    <div class="brand">
        <span class="brand-dot"></span>
        RECONX / SECURITY INTELLIGENCE
    </div>

    <h1>Reconnaissance Report</h1>

    <p>
        Authorized security reconnaissance and
        defensive web intelligence report.
    </p>

    <div class="target">
        TARGET :: {self.escape(session.target)}
    </div>

</header>

{stats}

{modules_html}

{errors_html}

<footer>
    Generated by
    <strong>ReconX</strong>
    · Authorized Security Reconnaissance Framework
    · DEV BY LORD MINATO
</footer>

</div>

</body>
</html>
"""

    def generate(
        self,
        session: ScanSession,
    ) -> Path:
        target_directory = (
            self.output_dir
            / safe_filename(session.target)
        )

        target_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        report_path = (
            target_directory
            / "report.html"
        )

        report_path.write_text(
            self.build(session),
            encoding="utf-8",
        )

        return report_path
