# ⚡ ReconX

> **Authorized Security Reconnaissance Framework**  
> **DEV BY LORD MINATO**

ReconX is a terminal-first reconnaissance framework built for **authorized security testing, defensive analysis, and security research**.

It collects useful intelligence from DNS, public Certificate Transparency data, HTTP responses, TLS certificates, web technologies, security headers, publicly visible endpoints, and observable exposure indicators.

<p align="center">
  <a href="https://github.com/minatonamikaze359/ReconX">
    <img src="https://img.shields.io/github/stars/minatonamikaze359/ReconX?style=for-the-badge&color=cyan" alt="GitHub Stars">
  </a>
  <a href="https://github.com/minatonamikaze359/ReconX">
    <img src="https://img.shields.io/github/forks/minatonamikaze359/ReconX?style=for-the-badge" alt="GitHub Forks">
  </a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

---

## 🖥️ ReconX

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██████╔╝██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██╔══██╗██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝

             W E L C O M E   T O   R E C O N X
                 AUTHORIZED SECURITY RECON
                       DEV BY LORD MINATO
```

---

# 📚 Complete Usage Tutorial

This guide takes you from **zero → installed → first scan → module scans → reports**.

---

## 1. 📋 Requirements

Before installing ReconX, make sure you have:

- Windows, Linux, or macOS
- Python **3.10 or newer**
- Git
- Internet access for network-based reconnaissance modules
- Authorization to assess the target

Check Python:

```bash
python --version
```

On some Linux/macOS systems:

```bash
python3 --version
```

Check Git:

```bash
git --version
```

---

# 2. 📥 Download ReconX

Clone the official repository:

```bash
git clone https://github.com/minatonamikaze359/ReconX.git
```

Enter the project:

```bash
cd ReconX
```

Check the files:

```bash
dir
```

Windows PowerShell/CMD should show files such as:

```text
main.py
requirements.txt
README.md
reconx/
```

On Linux/macOS use:

```bash
ls
```

---

# 3. 🐍 Create a Virtual Environment

A virtual environment keeps ReconX dependencies isolated from your system Python installation.

## Windows

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\\Scripts\\activate
```

You should see:

```text
(.venv) PS F:\ReconX\ReconX>
```

## Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

# 4. 📦 Install Dependencies

With the virtual environment activated:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

ReconX currently uses:

| Package | Purpose |
|---|---|
| Rich | Terminal UI, tables, panels and output |
| Requests | HTTP communication |
| dnspython | DNS intelligence |
| BeautifulSoup | HTML parsing |
| tldextract | Domain parsing utilities |

Verify the installation:

```bash
pip list
```

---

# 5. 🚀 Start ReconX

Run:

```bash
python main.py
```

ReconX will display the startup interface:

```text
RECONX
WELCOME TO RECONX
AUTHORIZED SECURITY RECON
DEV BY LORD MINATO

[ SYSTEM ] Initializing ReconX Engine...
[ SYSTEM ] Loading reconnaissance modules...
[ SYSTEM ] Initializing security checks...
[ SYSTEM ] Preparing terminal interface...
[ SYSTEM ] ReconX Engine ready.

ReconX interactive mode
Type 'help' for commands or 'exit' to quit.

reconx >
```

You are now inside the ReconX interactive terminal.

---

# 6. 🆘 Get Help

From the normal PowerShell terminal:

```bash
python main.py help
```

Or from the ReconX interactive prompt:

```text
reconx > help
```

You will see the available command categories.

---

# 7. ℹ️ Check the Version

PowerShell:

```bash
python main.py version
```

Interactive mode:

```text
reconx > version
```

Example:

```text
ReconX v1.0.0
Authorized Security Reconnaissance Framework
DEV BY LORD MINATO
```

---

# 8. 🧩 View Available Modules

Run:

```bash
python main.py modules
```

The current module set is:

```text
01  dns
02  subdomains
03  certificates
04  http
05  technologies
06  headers
07  endpoints
08  exposure
```

---

# 9. 🛡️ Authorization Requirement

ReconX requires explicit authorization confirmation for scans.

Before scanning a target, make sure you:

- Own the target, **or**
- Have explicit permission to assess it.

ReconX uses:

```text
--authorized
```

as an explicit confirmation.

For example:

```bash
python main.py scan YOUR-AUTHORIZED-DOMAIN.COM --authorized
```

Do not use ReconX against systems you are not authorized to assess.

---

# 10. 🎯 Your First Scan

For an authorized target:

```bash
python main.py scan YOUR-DOMAIN.COM --authorized
```

Example using a domain you control:

```bash
python main.py scan example.com --authorized
```

The engine will:

1. Parse the target.
2. Validate the hostname.
3. Check the authorization flag.
4. Create a scan session.
5. Load the reconnaissance modules.
6. Execute the selected modules.
7. Collect results.
8. Generate JSON, Markdown and HTML reports.

A successful scan looks similar to:

```text
══════════════════════════════════════════
TARGET: example.com
URL: https://example.com
MODULES: 8
══════════════════════════════════════════

[ MODULE ] DNS Intelligence
[ + ] dns completed

[ MODULE ] Subdomain Discovery
[ + ] subdomains completed

[ MODULE ] Certificate Intelligence
[ + ] certificates completed

[ MODULE ] HTTP Analysis
[ + ] http completed

[ MODULE ] Technology Detection
[ + ] technologies completed

[ MODULE ] Security Headers
[ + ] headers completed

[ MODULE ] Endpoint Discovery
[ + ] endpoints completed

[ MODULE ] Exposure Analysis
[ + ] exposure completed

✔ ReconX scan completed.
```

---

# 11. 🔬 Scan Only One Module

You don't always need to run every module.

Use:

```bash
python main.py scan YOUR-DOMAIN.COM --module MODULE --authorized
```

For example, DNS:

```bash
python main.py scan YOUR-DOMAIN.COM --module dns --authorized
```

HTTP:

```bash
python main.py scan YOUR-DOMAIN.COM --module http --authorized
```

Security headers:

```bash
python main.py scan YOUR-DOMAIN.COM --module headers --authorized
```

Technology detection:

```bash
python main.py scan YOUR-DOMAIN.COM --module technologies --authorized
```

Endpoint discovery:

```bash
python main.py scan YOUR-DOMAIN.COM --module endpoints --authorized
```

Exposure analysis:

```bash
python main.py scan YOUR-DOMAIN.COM --module exposure --authorized
```

---

# 12. 🔥 Run All Reconnaissance Modules

To explicitly request the complete module suite:

```bash
python main.py scan YOUR-DOMAIN.COM --all --authorized
```

This runs:

```text
DNS
Subdomains
Certificates
HTTP
Technologies
Headers
Endpoints
Exposure
```

---

# 13. 🧬 DNS Module

The DNS module checks:

- A
- AAAA
- CNAME
- MX
- NS
- TXT
- SOA

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module dns --authorized
```

The generated file is:

```text
reconx-report/
└── YOUR-DOMAIN.COM/
    └── dns.json
```

---

# 14. 🌐 Subdomain Module

ReconX uses passive Certificate Transparency information from crt.sh.

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module subdomains --authorized
```

The result includes discovered subdomains observed in certificate data.

No brute-force subdomain wordlist attack is performed.

Output:

```text
subdomains.json
```

---

# 15. 🔐 Certificate Module

The certificate module performs normal TLS inspection.

It can collect information such as:

- Certificate subject
- Issuer
- Serial number
- Validity dates
- Subject Alternative Names
- TLS version
- Cipher information
- Validity status

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module certificates --authorized
```

Output:

```text
certificates.json
```

---

# 16. 🌍 HTTP Module

The HTTP module performs low-impact HTTP/HTTPS analysis.

It records information such as:

- HTTP status code
- Final URL
- Redirects
- Response time
- Content type
- Content length
- Server header
- Response headers
- HTTP version information

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module http --authorized
```

Output:

```text
http.json
```

---

# 17. 🧠 Technology Module

ReconX looks for passive technology indicators in:

- HTTP response headers
- HTML
- Generator metadata
- Common framework/resource signatures

Examples of detectable technologies include:

```text
WordPress
Drupal
Joomla
Next.js
Nuxt
React
Vue.js
Angular
jQuery
Bootstrap
Tailwind CSS
```

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module technologies --authorized
```

Output:

```text
technologies.json
```

---

# 18. 🛡️ Security Headers Module

ReconX checks commonly used defensive headers, including:

```text
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Cross-Origin-Opener-Policy
Cross-Origin-Resource-Policy
Cross-Origin-Embedder-Policy
```

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module headers --authorized
```

The report distinguishes observed and missing headers.

Output:

```text
headers.json
```

> Missing headers are observations, not automatically proof of a vulnerability. Web applications may have legitimate deployment-specific requirements.

---

# 19. 🔗 Endpoint Module

The endpoint module extracts publicly visible information from accessible HTML.

It can identify:

- Same-host links
- Forms
- Form actions
- Form input names/types
- JavaScript files
- Stylesheets
- Images
- Canonical metadata
- Robots metadata
- Sitemap location

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module endpoints --authorized
```

Output:

```text
endpoints.json
```

ReconX does **not** brute-force hidden paths.

---

# 20. 👁️ Exposure Module

The exposure module performs defensive observations from normal HTTP responses.

It checks for things such as:

- Technology disclosure headers
- Runtime/version disclosure headers
- HTTP instead of HTTPS
- Missing observed HSTS
- Publicly accessible standard resources
- Restricted responses for standard resources

Interesting standard resources include:

```text
/robots.txt
/sitemap.xml
/.well-known/security.txt
```

Run:

```bash
python main.py scan YOUR-DOMAIN.COM --module exposure --authorized
```

Output:

```text
exposure.json
```

---

# 21. 📊 Understanding Reports

After a scan, ReconX automatically creates:

```text
reconx-report/
└── example.com/
    ├── summary.json
    ├── dns.json
    ├── subdomains.json
    ├── certificates.json
    ├── http.json
    ├── technologies.json
    ├── headers.json
    ├── endpoints.json
    ├── exposure.json
    ├── report.md
    └── report.html
```

---

# 22. 🧾 JSON Reports

JSON is useful when you want to process results programmatically.

Example:

```json
{
    "target": "example.com",
    "status": "completed",
    "modules": [
        "dns",
        "http"
    ]
}
```

The main file is:

```text
summary.json
```

Each reconnaissance module also gets its own JSON file.

---

# 23. 📝 Markdown Report

ReconX generates:

```text
report.md
```

You can open it with:

- VS Code
- Notepad++
- Any Markdown editor
- GitHub

It provides a readable summary of the reconnaissance session.

---

# 24. 🌌 HTML Report

ReconX also generates:

```text
report.html
```

Open it directly in your browser.

Windows:

```powershell
start .\\reconx-report\\example.com\\report.html
```

Or navigate manually to:

```text
F:\ReconX\ReconX\reconx-report\example.com\report.html
```

The HTML report provides a dark ReconX-style dashboard containing the collected results.

---

# 25. 📚 Report Archive

To list all previously generated reports:

```bash
python main.py report
```

Example:

```text
ReconX Report Archive

#   Target          Formats
1   example.com     json, markdown, html
2   testsite.com    json, markdown, html
```

---

# 26. 🔍 View One Target's Report

Use:

```bash
python main.py report example.com
```

ReconX will show the report directory and available files.

Example:

```text
RECONX REPORT

Target: example.com
Directory:
F:\ReconX\ReconX\reconx-report\example.com

JSON:
...\\summary.json

Markdown:
...\\report.md

HTML:
...\\report.html
```

---

# 27. 🖥️ Interactive Mode Commands

Start:

```bash
python main.py
```

Then use:

```text
reconx > help
reconx > version
reconx > modules
reconx > report
reconx > report example.com
reconx > exit
```

### Important

The `reconx >` prompt is ReconX's interactive command interface. Do **not** paste PowerShell commands such as:

```text
reconx > python main.py scan example.com --authorized
```

Instead, run the full `python main.py ...` command from PowerShell/CMD.

For scans, the current supported and documented path is the direct CLI command:

```bash
python main.py scan example.com --authorized
```

---

# 28. 🧪 Recommended First-Time Test

If you are setting up ReconX for the first time, follow this exact sequence.

### Step 1

```bash
git clone https://github.com/minatonamikaze359/ReconX.git
cd ReconX
```

### Step 2

Windows:

```powershell
python -m venv .venv
.venv\\Scripts\\activate
```

### Step 3

```bash
pip install -r requirements.txt
```

### Step 4

```bash
python main.py version
```

### Step 5

```bash
python main.py modules
```

### Step 6

Run an authorized test:

```bash
python main.py scan YOUR-AUTHORIZED-DOMAIN.COM --authorized
```

### Step 7

Check reports:

```bash
python main.py report
```

### Step 8

Open the HTML report in your browser.

---

# 29. 🧯 Common Problems

## Python is not recognized

Try:

```bash
py --version
```

If `py` works, you can use:

```bash
py -m venv .venv
py main.py
```

Install Python from the official Python distribution if neither command works.

---

## Git is not recognized

Install Git, then reopen your terminal.

Check:

```bash
git --version
```

---

## PowerShell blocks virtual environment activation

If PowerShell reports an execution-policy error, you can use Command Prompt instead:

```cmd
.venv\\Scripts\\activate.bat
```

Or use an appropriate PowerShell execution-policy configuration for your own machine.

---

## Dependencies are missing

Make sure the virtual environment is active:

```text
(.venv)
```

Then:

```bash
pip install -r requirements.txt
```

---

## A scan fails

ReconX records module failures and continues where possible.

Check the terminal output and generated:

```text
summary.json
```

for scan status and errors.

Network connectivity, DNS availability, TLS configuration, redirects, and remote-server behavior can affect individual modules.

---

# 30. 🏗️ Project Structure

```text
ReconX/
│
├── main.py
├── requirements.txt
├── README.md
│
├── reconx/
│   ├── __init__.py
│   ├── banner.py
│   ├── colors.py
│   ├── animations.py
│   ├── config.py
│   ├── utils.py
│   ├── cli.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── target.py
│   │   ├── permissions.py
│   │   └── session.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── dns.py
│   │   ├── subdomains.py
│   │   ├── certificates.py
│   │   ├── http.py
│   │   ├── technologies.py
│   │   ├── headers.py
│   │   ├── endpoints.py
│   │   └── exposure.py
│   │
│   └── reporting/
│       ├── __init__.py
│       ├── json_report.py
│       ├── markdown_report.py
│       ├── html_report.py
│       └── manager.py
│
└── reconx-report/
    └── <target>/
        ├── summary.json
        ├── *.json
        ├── report.md
        └── report.html
```

---

# ✨ Features

## 🔎 Reconnaissance

- DNS intelligence
- Passive subdomain discovery
- Certificate Transparency discovery
- TLS certificate inspection
- HTTP analysis
- Technology detection
- Security-header analysis
- Public endpoint discovery
- Defensive exposure analysis

## 🎨 Terminal Experience

- Hacker-style startup banner
- Rich terminal interface
- Colored status messages
- Module progress output
- Scan timing
- Interactive command mode
- Report archive

## 📊 Reporting

- Structured JSON
- Markdown reports
- HTML dashboard reports
- Per-target report directories
- Scan summaries
- Module-specific results
- Error tracking

---

# 🛡️ Responsible Use

ReconX is intended for **authorized security testing and defensive research only**.

Use it only when you:

- Own the target, or
- Have explicit permission to assess the target.

ReconX intentionally focuses on low-impact reconnaissance and defensive analysis.

It does **not** provide:

- Exploit payloads
- Credential theft
- Persistence
- Destructive actions
- Brute-force attacks
- Security-control bypasses
- Unauthorized access

Always comply with applicable laws, contracts, rules, and terms of service.

---

# ⭐ Support the Project

If ReconX is useful to you:

## ⭐ Star the repository

A star helps the project gain visibility.

**ReconX:**  
https://github.com/minatonamikaze359/ReconX

## 🍴 Fork the project

Fork ReconX to experiment with your own authorized modules and improvements.

## 🐛 Report bugs

Found a reproducible problem?

Open a GitHub Issue with:

- Operating system
- Python version
- ReconX version
- Command used
- Complete error output

## 💡 Request features

Suggestions for passive intelligence, reporting, CLI, and defensive-analysis improvements are welcome.

## 🤝 Contribute

Pull requests are welcome for improvements that remain within the project's authorized and defensive scope.

---

# 🤝 Contributing

1. Fork the repository.
2. Clone your fork.
3. Create a feature branch.
4. Make your changes.
5. Test locally.
6. Document your changes.
7. Commit your work.
8. Push your branch.
9. Open a Pull Request.

Example:

```bash
git checkout -b feature/my-module
git add .
git commit -m "Add new reconnaissance feature"
git push origin feature/my-module
```

Then create a Pull Request on GitHub.

---

# 🗺️ Roadmap

Planned improvements may include:

- [ ] More passive intelligence modules
- [ ] Improved technology fingerprints
- [ ] Better HTML report visualizations
- [ ] Report comparison
- [ ] Scan history
- [ ] Configurable module profiles
- [ ] More CLI output controls
- [ ] Global `reconx` command
- [ ] Automated testing
- [ ] Additional defensive analysis
- [ ] Improved interactive scan commands

---

# 👑 Developer

**DEV BY LORD MINATO**

Built with Python, Rich, Requests, dnspython, BeautifulSoup and a focus on clean terminal-based security tooling.

---

# 📜 License

This project is intended to be released under the **MIT License**.

See the repository for the complete license text.

---

<p align="center">

### ⚡ ReconX

**AUTHORIZED SECURITY RECONNAISSANCE**

**DEV BY LORD MINATO**

⭐ Star the repository if you find it useful.

</p>
