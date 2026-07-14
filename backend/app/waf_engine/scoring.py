from typing import Dict, List
from app.config import Config

class AdaptiveRiskScorer:
    """
    Synthesizes normalized risk scores from all 6 AMRSF detection layers into
    a unified Final Risk Score (0-100) and assigns an actionable Decision Tier.
    """
    def __init__(self):
        self.w_sig = Config.WAF_WEIGHT_SIGNATURE
        self.w_enc = Config.WAF_WEIGHT_ENCODING
        self.w_comp = Config.WAF_WEIGHT_COMPLEXITY
        self.w_ml = Config.WAF_WEIGHT_ML
        self.w_beh = Config.WAF_WEIGHT_BEHAVIORAL
        self.w_threat = Config.WAF_WEIGHT_THREAT_INTEL

    def calculate_final_score(self, scores: Dict[str, float]) -> Dict:
        """
        Calculates final weighted risk score (0-100), penalty boosters, and decision tier.
        """
        s_sig = scores.get("signature_score", 0.0)
        s_enc = scores.get("encoding_suspicion", 0.0)
        s_comp = scores.get("payload_complexity", 0.0)
        s_ml = scores.get("ml_confidence", 0.0)
        s_beh = scores.get("behavioral_score", 0.0)
        s_threat = scores.get("threat_intel_score", 0.0)

        # Base weighted summation
        weighted_sum = (
            self.w_sig * s_sig +
            self.w_enc * s_enc +
            self.w_comp * s_comp +
            self.w_ml * s_ml +
            self.w_beh * s_beh +
            self.w_threat * s_threat
        )

        # Omega non-linear penalty booster
        # If any deterministic signature confirms critical attack OR ML + complexity are both high
        penalty = 0.0
        high_signal_count = sum(1 for s in [s_sig, s_ml, s_enc, s_threat] if s >= 75.0)
        if high_signal_count >= 2:
            penalty += 25.0
        elif s_sig >= 90.0:
            penalty += 20.0

        final_score = min(100.0, max(0.0, weighted_sum + penalty))

        # Assign Decision Tier (0-25 Allow, 26-50 Monitor, 51-75 Challenge, 76-100 Block)
        if final_score <= Config.THRESHOLD_ALLOW_MAX:
            decision = "Allow"
            action = "Forward request normally to origin server"
        elif final_score <= Config.THRESHOLD_MONITOR_MAX:
            decision = "Monitor"
            action = "Forward request with X-WAF-Risk: Monitor log tag"
        elif final_score <= Config.THRESHOLD_CHALLENGE_MAX:
            decision = "Challenge"
            action = "Issue CAPTCHA / Strict HTTP 429 Rate Limit Challenge"
        else:
            decision = "Block"
            action = "Instant HTTP 403 Forbidden Block & IP Watchlist Quarantine"

        return {
            "final_risk_score": round(final_score, 1),
            "decision": decision,
            "action_taken": action,
            "penalty_boost": round(penalty, 1)
        }
