<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&duration=3000&pause=1000&color=64FFDA&center=true&vCenter=true&width=750&lines=RAPTOR+EDR;Endpoint+Detection+%26+Response;YAML+Rule+Engine+%7C+ML+Classifier;14+MITRE+ATT%26CK+Techniques+Covered" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Lightweight EDR platform with YAML detection rules, heuristic ML threat classification, and automated response actions.**

<br/>

[![Rules](https://img.shields.io/badge/Detection_Rules-14_YAML-64ffda?style=flat-square)](.)
[![MITRE](https://img.shields.io/badge/MITRE_Techniques-14-64ffda?style=flat-square)](.)
[![Classifier](https://img.shields.io/badge/ML_Classifier-Shannon_Entropy-64ffda?style=flat-square)](.)
[![Air_Gap](https://img.shields.io/badge/Air--Gap-Capable-22c55e?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Commercial EDR agents cost **$30–50 per endpoint per year** with heavyweight kernel drivers and cloud telemetry. RAPTOR EDR provides:

- **Real-time telemetry ingestion** from any agent or syslog forwarder
- **YAML detection rules** (Sigma-compatible) covering 14 MITRE techniques
- **Heuristic ML classifier** — Shannon entropy, process risk scoring, no pre-trained models
- **Automated response** — endpoint isolation, process kill, forensic collection
- **Zero external API dependencies** — fully air-gap capable

| Feature | Details |
|---------|---------|
| **Detection Rules** | 14 YAML rules — Persistence, Lateral Movement, Exfiltration |
| **ML Classifier** | Shannon entropy + process risk + cmdline heuristics |
| **Response Actions** | isolate, kill_process, collect_forensics, block_hash |
| **Alert Dedup** | MD5-keyed 5-minute sliding window |
| **Batch Ingestion** | Up to 1,000 events per API call |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Endpoint Agent (any platform)
        │  POST /api/event  or  /api/event/batch
        ▼
┌───────────────────────────────────────────┐
│            Event Processor                │
│   Normalize │ Enrich │ Timestamp          │
└──────────────────┬────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐   ┌────────────────────┐
│  YAML Rule    │   │  ML Threat         │
│  Engine       │   │  Classifier        │
│  14 rules     │   │  Shannon entropy   │
│  3 tactic files│  │  Process risk score│
└───────┬───────┘   └──────────┬─────────┘
        └──────────┬───────────┘
                   │
        ┌──────────▼──────────┐
        │   Alert Manager     │
        │   Dedup (5 min)     │
        │   Severity assign   │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │   Response Engine   │
        │   isolate / kill /  │
        │   collect / block   │
        └─────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Detection Rules

<details>
<summary><b>🔒 Persistence (5 rules)</b></summary>

| Rule | Name | MITRE |
|------|------|-------|
| persist-001 | Registry Run Key Persistence | T1547.001 |
| persist-002 | Startup Folder Dropper | T1547.001 |
| persist-003 | Scheduled Task Creation | T1053.005 |
| persist-004 | Cron Job Persistence | T1053.003 |
| persist-005 | SSH Authorized Keys Modification | T1098.004 |

</details>

<details>
<summary><b>🔀 Lateral Movement (5 rules)</b></summary>

| Rule | Name | MITRE |
|------|------|-------|
| lateral-001 | PsExec Remote Execution | T1021.002 |
| lateral-002 | Credential Dumping (Mimikatz) | T1003.001 |
| lateral-003 | WMI Lateral Movement | T1047 |
| lateral-004 | SMB File Transfer | T1021.002 |
| lateral-005 | SSH Lateral Movement | T1021.004 |

</details>

<details>
<summary><b>📤 Exfiltration (4 rules)</b></summary>

| Rule | Name | MITRE |
|------|------|-------|
| exfil-001 | HTTP/S Upload (curl/wget) | T1041 |
| exfil-002 | Archive Sensitive Directories | T1560.001 |
| exfil-003 | DNS Tunneling | T1048.003 |
| exfil-004 | SMTP Exfiltration | T1048.002 |

</details>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/raptor.git
cd raptor

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5004
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/raptor.git
cd raptor
docker build -t raptor .
docker run -p 5004:5004 raptor
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Register endpoint
POST /api/endpoint/register
{"hostname": "WORKSTATION-01", "os": "Windows 10", "ip_address": "192.168.1.50"}

# Submit event
POST /api/event
{
  "endpoint_id": "<id>",
  "process_name": "powershell.exe",
  "cmdline": "powershell -enc SQBFAFgA",
  "username": "user",
  "network_dst_port": null
}

# Batch ingestion (up to 1000 events)
POST /api/event/batch

# Execute response action
POST /api/response
{"action": "isolate_endpoint", "target": "192.168.1.50", "alert_id": "<id>"}

# Metrics
GET /api/metrics
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
raptor/
├── app.py                      # Flask application & REST API
├── wsgi.py                     # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── rule_engine.py          # YAML detection rule engine
│   ├── threat_classifier.py    # Heuristic ML classifier
│   ├── event_processor.py      # Telemetry normalization
│   ├── alert_manager.py        # Deduplication & lifecycle
│   └── response_actions.py     # Automated response engine
│
├── rules/
│   ├── persistence_rules.yaml
│   ├── lateral_movement_rules.yaml
│   └── exfiltration_rules.yaml
│
├── templates/                  # Dashboard, Endpoints, Alerts
├── static/                     # CSS + JavaScript
└── tests/                      # 9 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Effective EDR doesn't require expensive agents — YAML rules, heuristic classifiers, and clean API design cover 80% of real threat scenarios."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/raptor?style=social)](https://github.com/RohitKumarReddySakam/raptor)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
