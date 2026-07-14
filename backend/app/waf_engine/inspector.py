from typing import Dict, Any
from app.waf_engine.signatures import SignatureEngine
from app.waf_engine.decoder import RecursiveDecoderEngine
from app.waf_engine.complexity import ComplexityAnalyzer
from app.waf_engine.ml_engine import ExplainableMLEngine
from app.waf_engine.behavioral import BehavioralEngine
from app.waf_engine.threat_intel import ThreatIntelModule
from app.waf_engine.scoring import AdaptiveRiskScorer

class WAFInspector:
    """
    AMRSF WAF Core Orchestrator.
    Executes a request through all 6 inspection layers in parallel/sequence,
    synthesizes scores, and outputs production-grade SHAP XAI logs and decisions.
    """
    def __init__(self):
        self.signatures = SignatureEngine()
        self.decoder = RecursiveDecoderEngine()
        self.complexity = ComplexityAnalyzer()
        self.ml_engine = ExplainableMLEngine()
        self.behavioral = BehavioralEngine()
        self.threat_intel = ThreatIntelModule()
        self.scorer = AdaptiveRiskScorer()

    def reload_rules(self, rules_list):
        """Reloads custom signature rules from database."""
        self.signatures.load_custom_rules(rules_list)

    def inspect_request(self, ip_address: str, method: str, url: str, headers: Dict[str, str], payload: str) -> Dict[str, Any]:
        """
        Main inspection entry point for HTTP requests.
        """
        # Layer 2: Recursive Decoding & Obfuscation Analysis
        dec_result = self.decoder.decode_payload(payload)
        decoded_payload = dec_result["decoded_payload"]
        s_enc = dec_result["encoding_suspicion"]

        # Layer 1: Signature & Rule Detection Engine (on both raw and decoded)
        sig_result = self.signatures.inspect(url, headers, decoded_payload)
        s_sig = sig_result["signature_score"]
        attack_category = sig_result["primary_category"]

        # Layer 3: Shannon Entropy & Payload Complexity Engine
        comp_result = self.complexity.analyze(url, decoded_payload)
        s_comp = comp_result["complexity_score"]

        # Layer 4: Explainable ML Engine + SHAP Feature Attribution
        ml_result = self.ml_engine.predict_with_shap(url, headers, decoded_payload, dec_result["encoding_depth"])
        s_ml = ml_result["ml_confidence"]

        # Layer 6: Threat Intelligence Lookup
        threat_result = self.threat_intel.lookup_ip(ip_address)
        s_threat = threat_result["threat_score"]

        # Layer 5: Behavioral Velocity Engine
        beh_result = self.behavioral.record_and_evaluate(ip_address, current_risk=max(s_sig, s_ml))
        s_beh = beh_result["behavioral_score"]

        # If attack category still generic but ML or Complexity high, classify accurately
        if attack_category == "Legitimate":
            if s_ml > 75.0 or s_comp > 75.0:
                attack_category = "Anomaly / High-Entropy Exploit"
            elif s_enc > 70.0:
                attack_category = "Obfuscated / Encoded Attack"

        # Combine scores via Adaptive Multi-Layer Risk Scoring Synthesizer
        score_dict = {
            "signature_score": s_sig,
            "encoding_suspicion": s_enc,
            "payload_complexity": s_comp,
            "ml_confidence": s_ml,
            "behavioral_score": s_beh,
            "threat_intel_score": s_threat
        }
        score_res = self.scorer.calculate_final_score(score_dict)

        # Aggregate natural language reasons
        all_reasons = []
        all_reasons.extend(sig_result["reasons"])
        all_reasons.extend(dec_result["reasons"])
        all_reasons.extend(comp_result["reasons"])
        all_reasons.extend(ml_result["reasons"])
        all_reasons.extend(beh_result["reasons"])
        all_reasons.extend(threat_result["reasons"])

        reason_summary = " | ".join(all_reasons) if all_reasons else "Normal legitimate traffic profile"

        return {
            "final_risk_score": score_res["final_risk_score"],
            "decision": score_res["decision"],
            "action_taken": score_res["action_taken"],
            "attack_category": attack_category,
            "scores_breakdown": score_dict,
            "reason": reason_summary,
            "shap_explanations": ml_result["shap_explanations"],
            "decoded_payload": decoded_payload,
            "encoding_depth": dec_result["encoding_depth"]
        }
