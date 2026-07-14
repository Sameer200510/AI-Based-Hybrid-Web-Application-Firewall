# AMRSF User & Administrator Manual

---

## 1. Security Operations Center (SOC) User Guide

### Live WAF Inspector & Explainable AI (XAI)
1. Open **Live WAF Inspector & XAI** tab in the top navigation.
2. Select any quick preset attack vector (e.g. *SQL Injection*, *XSS*, *Command Injection*, *SSTI*, *Obfuscated SQLi*) or type a custom HTTP method, target URI, and payload.
3. Click **Run AMRSF 6-Layer Inspection**.
4. Observe:
   - **Automated Decision Badge**: `ALLOW`, `MONITOR`, `CHALLENGE`, or `BLOCK`.
   - **Final Risk Score**: Normalized between `0` and `100`.
   - **6-Layer Breakdown Grid**: Signature Score, Encoding Suspicion, Shannon Complexity, ML Confidence, Behavioral Score, and Threat Intel Score.
   - **SHAP TreeExplainer Attribution**: Natural-language explanation and Shapley feature impact table ranking the exact lexical features that contributed to the classification.

---

## 2. Administrator Guide

### Rule Manager
1. Navigate to **Rule Manager**.
2. To create a new dynamic rule, enter the rule name, regular expression pattern (e.g. `(?i)\bunion\s+select`), threat category, and severity score.
3. Click **Deploy Rule to Engine**. The WAF engine reloads active rules immediately without server downtime.

### IEEE Research Laboratory
1. Navigate to **IEEE Research Lab**.
2. Choose the evaluation dataset sample size (e.g., `400 Samples`).
3. Click **Run Scientific Evaluation** to generate a balanced benchmark dataset modeled after CSIC 2010 and display comparative evaluation tables (Accuracy, Precision, Recall, F1, Latency) against ModSecurity CRS and Signature-Only WAF baselines.
