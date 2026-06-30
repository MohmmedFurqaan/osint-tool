<div align="center">

# 🕵️‍♂️ OSINT Scanner CLI

**A fast, asynchronous, and extensible Open Source Intelligence gathering tool.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Framework: Typer](https://img.shields.io/badge/CLI-Typer-009688.svg)](https://typer.tiangolo.com/)
[![Validation: Pydantic](https://img.shields.io/badge/Validation-Pydantic-e92063.svg)](https://docs.pydantic.dev/)

</div>

---

## 📖 Overview

**OSINT Scanner CLI** is an automated, command-line reconnaissance tool built in Python. Designed for security students, ethical hackers, and junior analysts, it rapidly gathers publicly available intelligence on a target website or domain without any active exploitation or unauthorized access.

Leveraging modern Python `asyncio` for maximum concurrency, the tool consolidates disparate reconnaissance steps into a single, lightning-fast execution and exports the findings into a machine-readable JSON format powered by strict Pydantic data models.

## ✨ Key Features

- **⚡ Asynchronous Execution**: Rapidly fetches network-bound data (DNS, WHOIS, HTTP) concurrently.
- **🌐 Comprehensive Reconnaissance**:
  - **WHOIS Lookups**: Domain registration, registrar, and expiry metadata.
  - **DNS Enumeration**: A, AAAA, MX, TXT (SPF/DMARC), NS, and CNAME records.
  - **SSL/TLS Analysis**: Certificate issuer, validity periods, and expiration status.
  - **HTTP Headers**: Identification of missing critical security headers (HSTS, CSP, etc.).
  - **Technology Detection**: Passive fingerprinting via `Server` and `X-Powered-By` headers.
  - **Shodan Integration**: Optional port and service exposure lookup via the Shodan API.
- **⚠️ Automated Risk Assessment**: A built-in rule engine categorizes security misconfigurations into Low, Medium, and High severities.
- **📄 Structured Output**: Easily exports comprehensive target data and risk findings into a `JSON` format for external parsing and integration.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** (Extremely fast Python package installer and resolver)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MohmmedFurqaan/osint-tool.git 
   cd osint-tool
   ```

2. **Sync project dependencies:**
   Using `uv`, you can easily install the locked dependencies.
   ```bash
   uv sync
   ```

### Configuration

To enable the optional Shodan module, you must provide a Shodan API key.
1. Copy the sample environment file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and add your Shodan API key:
   ```env
   SHODAN_API_KEY=your_api_key_here
   ```

---

## 🛠️ Usage

OSINT Scanner CLI features an intuitive, self-documenting interface built with Typer.

### Basic Scan
To perform a standard reconnaissance scan and view the output directly in your terminal:
```bash
uv run main.py scan example.com
```

### Generate JSON Report
To perform a scan and automatically save the results into a structured JSON file:
```bash
uv run main.py scan https://example.com --report
# Or using the shorthand flag:
uv run main.py scan https://example.com -r
```

*Reports are automatically saved to `data/output/<domain>_info.json`.*

### Help Menu
To view all available commands and flags:
```bash
uv run main.py --help
```

---

## 📁 Project Structure

```text
osint-tool/
├── data/
│   └── output/                 # Location of generated JSON reports
├── src/
│   └── osint/
│       ├── commands/           # CLI command definitions
│       ├── core/               # Orchestration layer (ScannerManager)
│       ├── models/             # Typed Pydantic data models
│       ├── services/           # Recon logic (whois, dns, ssl, shodan, etc.)
│       ├── validators/         # Input validation
│       └── utils/              # Shared helpers
├── .env                        # Environment variable configuration
├── main.py                     # Typer CLI Entrypoint
└── pyproject.toml              # Dependency definitions
```

---

## ⚖️ Security and Ethics

This tool is designed **strictly for educational and authorized assessment use only.** 

* **No Exploitation**: The tool collects purely public information and performs no exploitation, brute-forcing, or denial of service.
* **Authorization**: You must only use this tool against domains you own or have explicit written authorization to assess.
* **Disclaimer**: The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
<div align="center">
<i>Built for Skill Based Training (SBT) in defensive and educational cybersecurity tooling.</i>
</div>