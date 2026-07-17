# An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring for Intelligent Detection and Response to Web Attacks (AMRSF)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![React 18+](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![IEEE Research Grade](https://img.shields.io/badge/IEEE-Research%20Grade-00629B.svg)](./docs/IEEE_RESEARCH_SUMMARY.md)

---


## Executive Overview & Novelty

**AMRSF** is a next-generation, production-ready, research-grade **Explainable AI-Based Hybrid Web Application Firewall** designed to solve the critical dual limitations of conventional WAFs:
1. **Signature-only WAFs** (e.g., ModSecurity standard regex rules) suffer from high false negatives against zero-day exploits, obfuscated payloads, and multi-layer encodings.
2. **Black-box Machine Learning WAFs** lack interpretability, making it impossible for Security Operations Center (SOC) analysts to understand *why* legitimate traffic was blocked or *which exact lexical features* triggered an alert.

AMRSF introduces an **Adaptive Multi-Layer Risk Scoring Framework (AMRSF)** that inspects every HTTP request across **6 distinct detection layers**, fuses their signals into a unified **0–100 Final Risk Score**, triggers **Adaptive Automated Mitigation Responses**, and generates per-request **Explainable AI (SHAP TreeExplainer)** feature attributions.

---

## Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                    INCOMING HTTP REQUEST                                           |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                 ADAPTIVE MULTI-LAYER RISK SCORING FRAMEWORK (AMRSF PIPELINE)                       |
|                                                                                                    |
|  [Layer 1: Signatures]  --> 11 Attack Families (SQLi, XSS, CmdInj, PathTraversals, XXE, SSTI...)   |
|  [Layer 2: Decoding]    --> Recursive URL/Hex/Base64/Unicode & Comment Obfuscation Analyzer        |
|  [Layer 3: Complexity]  --> Shannon Entropy, Symbol Ratios, & AST Token Density                    |
|  [Layer 4: Explain ML]  --> LightGBM 32-Feature Classifier + SHAP TreeExplainer Attribution        |
|  [Layer 5: Behavioral]  --> Sliding Window Velocity Tracking, Error Probing & IP History           |
|  [Layer 6: Threat Intel]--> Real-time IP Reputation & Threat Feed Cross-Referencing                |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                SYNTHESIZED RISK SCORE (0 - 100) & ADAPTIVE DECISION ENGINE                         |
|                                                                                                    |
|  0 - 25: ALLOW      |  26 - 50: MONITOR    |  51 - 75: CHALLENGE  |  76 - 100: BLOCK               |
+----------------------------------------------------------------------------------------------------+
          |                              |                             |
          v                              v                             v
+-------------------+          +-------------------+          +--------------------------------------+
| Origin Web Server |          | Automated Mitigate|          | Security Dashboard & SHAP Explanation|
| (Allowed Request) |          | Rate Limit/IP Ban |          | (React + Vite + Tailwind + Recharts) |
+-------------------+          +-------------------+          +--------------------------------------+
```

---

## Key Features

- **Hybrid 6-Layer Detection Pipeline**:
  - Detects **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Command Injection**, **Path Traversal / LFI / RFI**, **XML External Entity (XXE)**, **Server-Side Template Injection (SSTI)**, **HTTP Parameter Pollution (HPP)**, **Encoded Attacks**, **Obfuscated Payloads**, and **Unknown Zero-Day Anomalies**.
- **Explainable AI (XAI) via SHAP**:
  - Every attack incident includes human-readable feature attributions indicating the exact percentage impact of each feature (e.g., *"SQL Keyword Count (+36.2%)"*, *"Shannon Entropy (+19.8%)"*, *"Double URL Encoding (+14.5%)"*).
- **Built-in IEEE Evaluation Laboratory**:
  - Generates high-fidelity benchmark datasets modeled after **CSIC 2010** and **HTTP Parameter Attack** datasets.
  - Computes scientific evaluation metrics: **Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix, False Positive/Negative Rates**, and **Latency comparison against ModSecurity and Signature-only baselines**.
- **Automated Attack Timeline Reconstruction**:
  - Correlates multi-stage attacks across time windows (e.g., Reconnaissance $\rightarrow$ Probing $\rightarrow$ Payload Execution $\rightarrow$ Block).
- **Premium Dark-Theme SOC Interface**:
  - Modern glassmorphism UI built with React, Vite, Tailwind CSS, and Recharts. Includes interactive Live WAF Request Inspector, Rule Manager, Model Lab, and Threat Geolocation Map.

---

## Project Structure

```
waf/
├── backend/
│   ├── app/
│   │   ├── config.py             # System configuration & environment variables
│   │   ├── database.py           # SQLAlchemy database setup
│   │   ├── models/               # ORM Models (RequestLog, AttackTimeline, WAFRule, ThreatIP)
│   │   ├── waf_engine/           # Core 6-Layer AMRSF Inspection Pipeline
│   │   │   ├── inspector.py      # Pipeline orchestrator
│   │   │   ├── signatures.py     # Layer 1: Compiled Signature Engine
│   │   │   ├── decoder.py        # Layer 2: Recursive Obfuscation Decoder
│   │   │   ├── complexity.py     # Layer 3: Shannon Entropy & Syntax Analyzer
│   │   │   ├── ml_engine.py      # Layer 4: Feature Extractor, LightGBM & SHAP Explainer
│   │   │   ├── behavioral.py     # Layer 5: Behavioral Velocity Engine
│   │   │   ├── threat_intel.py   # Layer 6: Threat Intelligence Integrations
│   │   │   └── scoring.py        # Adaptive Risk Scoring Synthesizer
│   │   ├── datasets/             # Built-in CSIC 2010 / HTTP dataset generator & IEEE evaluator
│   │   └── api/                  # REST API routes (/waf, /dashboard, /logs, /rules, /ml)
│   ├── run.py                    # Flask API server entry point
│   └── tests/                    # Comprehensive PyTest unit & integration tests
├── frontend/                     # React + Vite + Tailwind CSS SOC Dashboard
└── docker-compose.yml            # Complete Docker deployment setup
```

---

## Quick Start & Local Development

### 1. Backend Setup (Python / Flask)

```bash
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

pip install -r requirements.txt
python run.py
```
*The Backend API runs on `http://localhost:5000`.*
*Upon initial startup, the backend automatically initializes the SQLite/PostgreSQL database, synthesizes the IEEE training dataset, trains the LightGBM classifier, and primes the SHAP explainer.*

### 2. Frontend Setup (React / Vite)

```bash
cd frontend
npm install
npm run dev
```
*The Security Operations Center (SOC) Dashboard runs on `http://localhost:5173`.*

---

## API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/waf/inspect` | Inspect an HTTP request payload through all 6 layers & return SHAP XAI reasoning |
| `GET` | `/api/v1/dashboard/stats` | Live summary metrics, score distribution, and top attack vectors |
| `GET` | `/api/v1/dashboard/timeline` | Multi-stage attack timeline reconstructions |
| `GET` | `/api/v1/logs` | Paginated WAF inspection logs with full SHAP breakdown |
| `GET/POST` | `/api/v1/rules` | Manage WAF signature rules & inspect auto-generated permanent rule suggestions |
| `POST` | `/api/v1/ml/evaluate` | Trigger IEEE scientific evaluation vs ModSecurity & Signature WAF baselines |

---

## Citation & Research Use

When referencing this architecture in IEEE or academic publications, please cite:
> *"An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring for Intelligent Detection and Response to Web Attacks (AMRSF)"*, 2026.
