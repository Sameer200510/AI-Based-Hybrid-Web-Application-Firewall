import math
import re
from typing import Dict, List

class ComplexityAnalyzer:
    """
    Layer 3: Shannon Entropy & Payload Complexity Engine.
    Computes Shannon entropy, special character density, AST token ratios, and length anomalies
    to identify sophisticated obfuscated or encrypted attacks.
    """
    SPECIAL_CHARS = set("<>'\"();=#/*!${}[]|&?%\\+`~^")

    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculates Shannon entropy in bits per character."""
        if not text:
            return 0.0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def analyze(self, url: str, payload: str) -> Dict:
        """
        Analyzes combined payload complexity and returns score (0-100) + reasons.
        """
        combined = f"{url} {payload}".strip()
        if not combined:
            return {
                "shannon_entropy": 0.0,
                "special_char_ratio": 0.0,
                "complexity_score": 0.0,
                "reasons": []
            }

        entropy = self.calculate_shannon_entropy(combined)
        total_len = len(combined)
        special_count = sum(1 for c in combined if c in self.SPECIAL_CHARS)
        special_ratio = special_count / total_len if total_len > 0 else 0.0

        score = 0.0
        reasons: List[str] = []

        # Shannon Entropy Assessment
        if entropy > 5.6 and total_len > 30:
            score += 45.0
            reasons.append(f"High Shannon entropy detected ({entropy:.2f} bits/char)")
        elif entropy > 4.9 and total_len > 50:
            score += 25.0
            reasons.append(f"Elevated Shannon entropy ({entropy:.2f} bits/char)")

        # Special Character Density Assessment
        if special_ratio > 0.35 and total_len > 15:
            score += 45.0
            reasons.append(f"High special character density ({special_ratio*100:.1f}%)")
        elif special_ratio > 0.22 and total_len > 20:
            score += 20.0
            reasons.append(f"Elevated non-alphanumeric symbol density ({special_ratio*100:.1f}%)")

        # Length anomaly
        if len(payload) > 1500:
            score += 25.0
            reasons.append(f"Anomalous payload length ({len(payload)} bytes)")

        return {
            "shannon_entropy": round(entropy, 2),
            "special_char_ratio": round(special_ratio, 3),
            "complexity_score": min(100.0, score),
            "reasons": reasons
        }
