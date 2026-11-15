# AutoShield Pakistan

> **Accessible Cyber Hygiene. Stronger Digital Pakistan.**

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask%203.x-00d2b4.svg)](https://flask.palletsprojects.com/)
[![Database: SQLite](https://img.shields.io/badge/Database-SQLite%20WAL-lightgrey.svg)](https://www.sqlite.org/)

---

## Overview

**AutoShield Pakistan** is an open-source, automated cyber hygiene and defense auditing platform designed specifically for resource-constrained environments:

- Higher education institutions and computer science laboratories
- Small and medium-sized enterprises (SMEs)
- Non-governmental organizations (NGOs) and civic bodies
- Small IT and municipal administration departments

Many organizations lack dedicated cybersecurity personnel and frequently operate with basic vulnerabilities — open administrative ports, unpatched software, weak password configurations, and malicious browser extensions. AutoShield provides an automated, explainable, and local-first auditing suite that identifies these risks and provides actionable remediation guidance.

---

## Core Engineering Principles

1. **Safety by Design & Zero-Weaponization:** AutoShield conducts passive configuration analysis, static signature matching, and banner inspection. It **never** executes exploits, attempts brute-forcing, or dumps credentials.
2. **Local-First & Privacy-Preserving:** All audit records, network maps, and host metrics remain inside a local SQLite database (`instance/autoshield.db`). No telemetry or private organization data is transmitted outside.
3. **Verifiable Telemetry:** Operates without fabricated metrics. When audits are pending or system permissions limit inspection, the platform communicates this transparently.
4. **Cross-Platform Compatibility:** Designed to run reliably across Windows and Linux workstations with graceful degradation when optional low-level system drivers are absent.

---

## System Architecture

```
autoshield-pakistan/
│
├── app/
│   ├── __init__.py                # Flask application factory (SQLite WAL mode)
│   ├── config.py                  # Environment-specific configuration
│   ├── extensions.py              # SQLAlchemy, LoginManager, CSRF
│   │
│   ├── models/                    # Relational database models
│   │   ├── user.py                # Auditor authentication & role access
│   │   ├── asset.py               # Monitored hosts & subnet inventory
│   │   ├── scan.py                # Audit execution records & raw telemetry
│   │   ├── finding.py             # Security weaknesses & severity scoring
│   │   ├── remediation.py         # 5-step actionable remediation plans
│   │   ├── audit_log.py           # Immutable administrative action trail
│   │   └── yara_rule.py           # Static detection rule catalog
│   │
│   ├── modules/                   # Independent cybersecurity audit engines
│   │   ├── network/               # Socket & Scapy network inspection
│   │   ├── system/                # psutil system & firewall inspection
│   │   ├── password/              # Zero-knowledge policy evaluation
│   │   ├── browser/               # Extension manifest auditor
│   │   ├── software/              # Software inventory & advisory cross-check
│   │   ├── malware/               # Static YARA file & script inspection
│   │   └── risk_engine/           # Centralized risk calculation engine
│   │
│   ├── routes/                    # Web endpoints & view controllers
│   ├── templates/                 # Dark-themed responsive UI (Bootstrap 5)
│   ├── static/                    # CSS stylesheets & Chart.js assets
│   └── utils/                     # Defensive validators & platform helpers
│
├── rules/                         # Documented static detection rules (.yar)
├── tests/                         # Pytest test harness
├── instance/                      # Local SQLite database & generated reports
├── run.py                         # Application entrypoint (localhost bound)
└── requirements.txt               # Dependency manifest
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mariyamalikho/AutoShield-Pakistan.git
   cd AutoShield-Pakistan
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv

   # On Windows:
   .\.venv\Scripts\activate

   # On Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize configuration:**
   ```bash
   cp .env.example .env
   ```

5. **Launch AutoShield Pakistan:**
   ```bash
   python run.py
   ```
   Access the dashboard at `http://127.0.0.1:5000`.

---

## Running the Test Suite

```bash
pytest
```

---

## Security & Ethical Boundaries

AutoShield Pakistan is intended strictly for authorized defensive security assessments and educational purposes. Scanning networks, devices, or systems without explicit prior permission from the system owner is illegal and unethical. The software restricts scanning to private networks (RFC 1918) and local loopback by default.

---

## License

This project is licensed under the [MIT License](LICENSE).
