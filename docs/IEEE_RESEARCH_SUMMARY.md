# IEEE Research Summary & Patent Claims Architecture

## Project Title
**An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring for Intelligent Detection and Response to Web Attacks (AMRSF)**

---

## 1. Abstract
Modern Web Application Firewalls (WAFs) predominantly rely on deterministic regular expression signatures (e.g., ModSecurity CRS) or opaque machine learning classifiers. Signature-based detection suffers from high false-negative rates against novel encodings and zero-day variations, while black-box machine learning models introduce unacceptable false-positive risks without actionable interpretability for security analysts. 

In this research, we introduce **AMRSF (Adaptive Multi-Layer Risk Scoring Framework)**—an explainable, hybrid Web Application Firewall that synthesizes six complementary detection methodologies:
1. Deterministic Multi-Pattern Signature Matching (11 attack families)
2. Recursive Multi-Layer Decoding & Obfuscation Analysis
3. Shannon Entropy & Syntactic AST Complexity Metrics
4. Explainable Machine Learning (LightGBM + SHAP TreeExplainer Attribution)
5. Behavioral Request Velocity & Endpoint Traversal Profiling
6. Real-time Threat Intelligence Cross-Referencing

By dynamically weighting and fusing these six detection dimensions into a unified 0–100 Risk Score, AMRSF enables four granular response tiers (**Allow**, **Monitor**, **Challenge**, **Block**) and provides per-request explainable AI feature attribution via SHAP values. Empirical evaluation demonstrates superior F1 accuracy and lower latency compared to signature-only and generic ML baselines.

---

## 2. Mathematical Formulation of AMRSF

Let an incoming HTTP request be denoted as R = (Method, URI, Headers, QueryParams, Body, IP).

The total Adaptive Risk Score S_AMRSF(R) in [0, 100] is defined as:

S_AMRSF(R) = min(100, sum(w_i * Phi_i(R)) + Omega_penalty(R))

Where:
- Phi_1(R) = S_sig(R) in [0, 100]: Signature & Rule Detection Score across 11 threat families.
- Phi_2(R) = S_enc(R) in [0, 100]: Encoding & Obfuscation Suspicion Score (measuring multi-layer URL/Hex/Base64/Unicode encoding and comment obfuscation depth).
- Phi_3(R) = S_comp(R) in [0, 100]: Shannon Entropy & Payload Complexity Score.
- Phi_4(R) = S_ml(R) in [0, 100]: LightGBM Machine Learning Probability Confidence normalized to 100.
- Phi_5(R) = S_beh(R) in [0, 100]: Behavioral Velocity & Endpoint Anomaly Score.
- Phi_6(R) = S_threat(R) in [0, 100]: Threat Intelligence IP Reputation Score.
- w_1 ... w_6 are adaptive normalized weights such that sum(w_i) = 1.0 (Default weights: w_1=0.25, w_2=0.15, w_3=0.10, w_4=0.30, w_5=0.10, w_6=0.10).
- Omega_penalty(R): Non-linear booster penalty triggered when multiple high-severity layers cross critical thresholds simultaneously.

---

## 3. Decision Engine & Adaptive Response Matrix

| Final Risk Score (S_AMRSF) | Decision Tier | Automated Mitigation Action | Security Operation Center (SOC) Alert Level |
| :--- | :--- | :--- | :--- |
| **0 – 25** | **Allow** | Forward request to origin application server | None / Normal Audit Log |
| **26 – 50** | **Monitor** | Forward request, tag header X-WAF-Risk: Monitor, log full request payload | Low Severity SOC Event |
| **51 – 75** | **Challenge** | Issue HTTP 429 / strict CAPTCHA verification or aggressive rate limit | Medium Severity Alert + Behavioral Watchlist |
| **76 – 100** | **Block** | Instant HTTP 403 Forbidden, temporary IP quarantine, generate permanent rule suggestion | High/Critical Severity Alert + SHAP XAI Explanation |

---

## 4. Patent Innovation & Novelty Claims

### Claim 1: Multi-Layer Risk Fusion Architecture
A Web Application Firewall apparatus comprising a 6-layer parallel pipeline that calculates normalized risk sub-scores across deterministic signatures, recursive decoding depth, Shannon entropy, machine learning confidence, behavioral request velocity, and external threat feeds, fusing them into a single explainable 0–100 numerical risk metric.

### Claim 2: Real-Time SHAP Feature Attribution for Automated WAF Mitigation
An Explainable AI (XAI) security response method that extracts real-time TreeExplainer Shapley additive explanations for every blocked or challenged HTTP request, outputting human-readable natural language attributions ranking exact lexical and structural features responsible for attack classification.

### Claim 3: Automated Attack Campaign Reconstruction Timeline
A stateful correlation engine that reconstructs multi-stage attack campaigns across time windows, correlating initial reconnaissance (e.g., path traversal scanning) with payload probing and exploitation attempts into an interactive visual attack chain.
