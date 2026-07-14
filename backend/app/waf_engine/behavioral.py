import time
from collections import defaultdict, deque
from typing import Dict, List

class BehavioralEngine:
    """
    Layer 5: Behavioral Request Velocity & Endpoint Anomaly Engine.
    Tracks real-time sliding window request velocity per IP, burst patterns,
    and historical risk scores.
    """
    def __init__(self, window_seconds: int = 60, burst_threshold: int = 40):
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.ip_timestamps = defaultdict(deque)
        self.ip_history_risk = defaultdict(float)

    def record_and_evaluate(self, ip_address: str, current_risk: float = 0.0) -> Dict:
        """
        Records request arrival and computes behavioral risk score (0-100).
        """
        now = time.time()
        timestamps = self.ip_timestamps[ip_address]
        timestamps.append(now)

        # Prune old timestamps outside sliding window
        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        req_count = len(timestamps)
        score = 0.0
        reasons: List[str] = []

        # High request velocity assessment
        if req_count > self.burst_threshold * 2:
            score += 85.0
            reasons.append(f"High-velocity DoS/Brute-force burst detected ({req_count} req/min)")
        elif req_count > self.burst_threshold:
            score += 45.0
            reasons.append(f"Elevated request rate burst ({req_count} req/min)")

        # Historical IP risk carryover
        hist_risk = self.ip_history_risk[ip_address]
        if hist_risk > 60.0:
            score += 30.0
            reasons.append(f"Source IP has elevated historical threat profile (History={hist_risk:.1f})")

        # Update historical EMA risk
        self.ip_history_risk[ip_address] = (0.8 * hist_risk) + (0.2 * current_risk)

        return {
            "behavioral_score": min(100.0, score),
            "request_rate_rpm": req_count,
            "reasons": reasons
        }
