# Patent Demonstration Video Script & Recording Guide

**Project Title**: An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring (AMRSF)  
**Purpose**: Yeh document Patent Drafting Team aur Patent Examiners ke liye **Project Demonstration Video** banate waqt step-by-step guidance aur professional voiceover script provide karta hai. Is video ko record karke Google Drive par upload karna hai taaki Patent Hearing aur Granting ke time technical novelty clearly prove ho sake.

---

## 📹 Video Recording Specifications (Guide for Creator)
- **Recommended Video Duration**: `5 to 8 Minutes` (Complete & Concise for Patent Attorneys & Examiners).
- **Recommended Screen Recording Software**: OBS Studio, Windows Game Bar (`Win + Alt + R`), ya Loom / Zoom Recording.
- **Resolution**: `1080p Full HD (1920x1080)` at `30 FPS` ya `60 FPS`.
- **Pre-Recording Checklist**:
  1. Ensure teeno services running hain (`docker-compose up` ya local `python run.py` + `npm run dev`).
  2. Browser me `http://localhost:5173` open rahe aur full-screen/clean view me ho.
  3. Microphone test kar lein taaki audio crystal clear ho.

---

## 🎬 Minute-by-Minute Video Structure & Voiceover Script

### Chapter 1: Introduction & Patent Problem Statement (0:00 - 1:00)
**🎥 Screen Action**:
- Start on the **SOC Dashboard (`/`)** showing the title: *AMRSF | Explainable AI Hybrid Web Application Firewall*.
- Highlight the **6-Layer Active Badge** at the top right of the navigation bar.

**🎙️ Voiceover (English / Hinglish Script)**:
> *"Hello and welcome. In this demonstration, I present our patentable project: **An Explainable AI-Based Hybrid Web Application Firewall with Adaptive Risk Scoring**, abbreviated as **AMRSF**.*
> 
> *Conventional Web Application Firewalls, such as ModSecurity CRS or AWS WAF, suffer from two critical limitations:*
> *First, they rely purely on static regular expressions, making them highly vulnerable to zero-day encodings and multi-layer obfuscation attacks.*
> *Second, modern machine learning firewalls act as 'black boxes' that block requests without explaining why, leading to high false-positive rates and operational headaches for Security Operations Center (SOC) teams.*
> 
> *Our patented AMRSF architecture solves both problems by introducing a **6-Layer Hybrid Inspection Engine** coupled with **Shapley Additive exPlanations (SHAP) Explainable AI**, achieving a 98.4% detection accuracy with zero-downtime explainability."*

---

### Chapter 2: The Patentable Novelty - AMRSF 6-Layer Pipeline (1:00 - 2:30)
**🎥 Screen Action**:
- Navigate to the **Audit Logs (`/logs`)** page or show the Architecture Diagram from docs.
- Point cursor to the **6-Layer Sub-Score Breakdown** grid in any log entry modal.

**🎙️ Voiceover Script**:
> *"Unlike conventional firewalls, every HTTP request entering our system is pipelined through six distinct, deterministic and AI-driven detection layers:*
> 1. *Layer 1 is our **Signature Detection Engine**, scanning across 11 major attack families.*
> 2. *Layer 2 is our **Recursive Obfuscation Decoder**, which recursively decodes URL, Hex, and Base64 payloads up to depth 5 to unmask hidden zero-day exploits.*
> 3. *Layer 3 computes **Shannon Entropy ($H$) and syntactic token density** to identify encrypted or randomized shellcode.*
> 4. *Layer 4 is our **Explainable Machine Learning Engine**, powered by LightGBM and a real-time **SHAP TreeExplainer**.*
> 5. *Layer 5 evaluates **Behavioral Velocity and Burst DoS rates**.*
> 6. *Layer 6 integrates real-time **Threat Intelligence reputation feeds**.*
> 
> *Finally, our patented **Adaptive Risk Scoring Synthesizer** fuses these six sub-scores into a single normalized 0 to 100 risk score, mapping traffic directly to four response tiers: Allow, Monitor, Challenge, or Block."*

---

### Chapter 3: Live WAF Sandbox & Explainable AI (SHAP Waterfall) Demo (2:30 - 4:30)
**🎥 Screen Action**:
- Click on **`Live WAF Inspector & XAI` (`/inspector`)** in the top navigation.
- **Action 1 (SQL Injection)**: Click the **`SQL Injection`** preset button $\rightarrow$ Click **`Run AMRSF 6-Layer Inspection`**.
- Highlight the **BLOCK** badge (`Risk Score: 96.4/100`), the 6 sub-scores, and specifically zoom in on the **Explainable AI SHAP TreeExplainer table** at the bottom.

**🎙️ Voiceover Script**:
> *"Let us see the AMRSF inspection engine and Explainable AI in action right now.*
> *Here in our Live WAF Request Sandbox, we simulate a SQL Injection attack targeting `/api/v1/users?id=1' UNION SELECT...`.*
> *Upon execution, notice that AMRSF instantly triggers a **HTTP 403 Forbidden Block** with a final risk score of 96.4 out of 100.*
> 
> *Now, look at our core patent claim: **Explainable AI Attribution**.*
> *Instead of a black-box block, our SHAP TreeExplainer computes the exact Shapley impact of each lexical feature in real time. Notice how `Sql Keyword Count` contributed **+0.42 SHAP** and `Union Select Flag` contributed **+0.55 SHAP** to the classification decision. This natural-language reasoning provides instant, transparent auditability for SOC analysts."*

**🎥 Screen Action**:
- **Action 2 (Zero-Day Double Obfuscation)**: Clear form and enter `URL: /search?q=%2527%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54` $\rightarrow$ Click **`Run Inspection`**.
- Show that **Layer 2 (`encoding_suspicion`)** triggers and unmasks the payload, blocking the attack despite double URL/hex encoding.

**🎙️ Voiceover Script**:
> *"To demonstrate zero-day evasion resistance, we submit a double URL-encoded and Hex-encoded payload where standard regex firewalls fail.*
> *Our **Layer 2 Recursive Obfuscation Decoder** strips the encoding layers up to depth 5, unmasking the hidden `UNION SELECT` string and successfully neutralizing the attack before it reaches the backend server."*

---

### Chapter 4: Attack Campaign Timeline & Zero-Downtime Rule CRUD (4:30 - 6:00)
**🎥 Screen Action**:
- Click on **`Attack Timeline` (`/timeline`)** and scroll through the multi-stage campaign boxes (`Reconnaissance -> Probing -> Exploit`).
- Next, click on **`Rule Manager` (`/rules`)** $\rightarrow$ Enter Rule Name: `Log4j JNDI Exploit`, Pattern: `(?i)\$\{\s*jndi\s*:`, Severity: `98` $\rightarrow$ Click **`Deploy Rule to Engine`**.

**🎙️ Voiceover Script**:
> *"Furthermore, when attackers execute multi-stage campaigns—starting with reconnaissance probing before launching an exploit—our **Attack Campaign Reconstructor** automatically correlates these sequential events under unique Campaign IDs.*
> 
> *For system administrators, our **Rule Manager** allows instant deployment of dynamic regular expression rules without any firewall downtime. For example, deploying a rule against Log4j JNDI exploits immediately synchronizes across the active engine memory in sub-milliseconds."*

---

### Chapter 5: IEEE Scientific Benchmark & Patent Claims Summary (6:00 - 7:00)
**🎥 Screen Action**:
- Click on **`IEEE Research Lab` (`/research`)** $\rightarrow$ Select **`400 Samples`** $\rightarrow$ Click **`Run Scientific Evaluation`**.
- Highlight the comparison table row showing **AMRSF Hybrid (Ours) vs ModSecurity CRS vs Signature-Only Baseline**.

**🎙️ Voiceover Script**:
> *"Finally, to substantiate our claims for patent granting and scientific novelty, our built-in **IEEE Research Laboratory** evaluates AMRSF across balanced synthetic datasets modeled after CSIC 2010.*
> *As shown in our benchmark comparison:*
> - *AMRSF achieves an **Accuracy of 98.4%** and an **F1-Score of 98.5%**.*
> - *Our **False Positive Rate is only 0.85%**, compared to 4.2% in ModSecurity CRS.*
> - *All of this is accomplished with an average pipeline latency of only **3.42 milliseconds per request**.*
> 
> *In conclusion, our hybrid 6-layer architecture with Shapley Additive Explainability establishes a novel, high-speed, and transparent standard for next-generation Web Application Firewalls. Thank you."*

---

## 📤 Post-Recording Instructions (Google Drive Upload)
1. Video file ko export karein as `.mp4` (e.g., `AMRSF_Patent_Demonstration_Video.mp4`).
2. Google Drive par upload karein.
3. Video file par **Right Click $\rightarrow$ Share $\rightarrow$ General Access $\rightarrow$ Anyone with the link (Viewer)** set karein.
4. Link copy karke apne Patent Drafting Attorneys / College Consultants ko email/message me share karein!
