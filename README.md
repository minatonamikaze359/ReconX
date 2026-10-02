# ⚡ ReconX

> **Authorized Security Reconnaissance Framework**  
> **DEV BY LORD MINATO**

ReconX is a terminal-first reconnaissance framework built for **authorized security testing, defensive analysis, and security research**.

It provides a clean hacker-style CLI for collecting useful intelligence from DNS, public certificate data, HTTP responses, TLS certificates, web technologies, security headers, publicly visible endpoints, and observable exposure indicators.

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

## ✨ Features

### 🔎 Reconnaissance Modules

| Module | Description |
|---|---|
| 🧬 DNS | A, AAAA, CNAME, MX, NS, TXT and SOA intelligence |
| 🌐 Subdomains | Passive Certificate Transparency discovery |
| 🔐 Certificates | TLS certificate and connection metadata |
| 🌍 HTTP | Status, redirects, headers, timing and server information |
| 🧠 Technologies | Passive technology and framework detection |
| 🛡️ Headers | Security-header presence and configuration observations |
| 🔗 Endpoints | Publicly visible links, forms and web assets |
| 👁️ Exposure | Defensive exposure and information-disclosure analysis |

### 📊 Reporting

ReconX automatically generates structured reports:

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

Reports are available in:

- **JSON** — machine-readable results
- **Markdown** — readable security report
- **HTML** — dark ReconX dashboard-style report

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/minatonamikaze359/ReconX.git
cd ReconX
```

### 2. Create a virtual environment

#### Windows

```bash
python -m venv .venv
.venv\\Scripts\\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚡ Quick Start

Start the interactive ReconX terminal:

```bash
python main.py
```

You will enter:

```text
reconx >
```

Type:

```text
help
```

to see available commands.

---

## 🎯 Scan a Target

ReconX requires an explicit authorization confirmation before performing a scan.

```bash
python main.py scan example.com --authorized
```

### Run one module

```bash
python main.py scan example.com --module dns --authorized
```

Other modules:

```bash
python main.py scan example.com --module subdomains --authorized
python main.py scan example.com --module certificates --authorized
python main.py scan example.com --module http --authorized
python main.py scan example.com --module technologies --authorized
python main.py scan example.com --module headers --authorized
python main.py scan example.com --module endpoints --authorized
python main.py scan example.com --module exposure --authorized
```

### Run the full reconnaissance suite

```bash
python main.py scan example.com --all --authorized
```

---

## 📁 View Reports

List previously generated reports:

```bash
python main.py report
```

View reports for a specific target:

```bash
python main.py report example.com
```

Interactive mode also supports:

```text
reconx > report
reconx > report example.com
```

---

## 🧰 Other Commands

### Show version

```bash
python main.py version
```

### Show modules

```bash
python main.py modules
```

### Show help

```bash
python main.py help
```

---

## 🏗️ Project Structure

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

## 🛡️ Authorization & Responsible Use

ReconX is designed for **authorized security testing only**.

Use it only when you:

- Own the target, or
- Have explicit permission to assess the target.

ReconX is intentionally focused on low-impact reconnaissance and defensive analysis. It does **not** provide exploit payloads, credential theft, persistence, destructive actions, brute-force attacks, or security-control bypasses.

Always respect applicable laws, contracts, rules, and terms of service.

---

## ⭐ Support ReconX

If you find ReconX useful, you can support the project by:

### ⭐ Star the repository

A GitHub star helps people discover the project.

**Repository:**  
https://github.com/minatonamikaze359/ReconX

### 🍴 Fork it

Create your own version and experiment with new authorized reconnaissance modules.

### 🐛 Report bugs

Open an issue if you find a reproducible bug or unexpected behavior.

### 💡 Suggest features

Ideas for new passive reconnaissance, reporting, or defensive-analysis features are welcome.

### 🔧 Contribute

Pull requests are welcome for improvements that stay within the project's authorized and defensive scope.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test your changes locally.
5. Keep modules focused and documented.
6. Submit a pull request.

Example:

```bash
git checkout -b feature/my-module
git add .
git commit -m "Add new reconnaissance feature"
git push origin feature/my-module
```

Then open a Pull Request on GitHub.

---

## 🗺️ Roadmap

Planned improvements may include:

- [ ] More passive intelligence modules
- [ ] Improved technology fingerprints
- [ ] Better HTML report visualizations
- [ ] Report comparison
- [ ] Scan history
- [ ] Configurable module profiles
- [ ] More CLI output controls
- [ ] Packaging as a global `reconx` command
- [ ] Automated testing
- [ ] Additional defensive analysis

---

## 👑 Developer

**DEV BY LORD MINATO**

Built with Python, Rich, Requests, dnspython, BeautifulSoup and a focus on clean terminal-based security tooling.

---

## 📜 License

This project is intended to be released under the **MIT License**.

See the repository for the complete license text.

---

<p align="center">

### ⚡ ReconX

**AUTHORIZED SECURITY RECONNAISSANCE**

**DEV BY LORD MINATO**

⭐ Star the repo if you find it useful.

</p>
