import os
import requests
from cachetools import TTLCache
from typing import Dict, List
from app.config import Config

class ThreatIntelModule:
    """
    Layer 6: Threat Intelligence Cross-Referencing Module.
    Queries cached IP reputation feeds (AbuseIPDB, VirusTotal, AlienVault OTX ready)
    and automatically boosts risk score for known malicious IPs.
    """
    def __init__(self):
        # 1-hour TTL cache for up to 2048 IP lookups
        self.ip_cache = TTLCache(maxsize=2048, ttl=3600)
        # Seed known test malicious IP ranges
        self.seed_mock_threats()

    def seed_mock_threats(self):
        """Seeds common testing or Tor/Botnet IPs for instant demonstration."""
        self.ip_cache["185.220.101.5"] = {"score": 95.0, "category": "Tor Exit Node / Malicious Scanner"}
        self.ip_cache["198.51.100.24"] = {"score": 88.0, "category": "AbuseIPDB Reported SQLi Bot"}
        self.ip_cache["203.0.113.195"] = {"score": 92.0, "category": "Known Automated Exploit Scanner"}

    def lookup_ip(self, ip_address: str) -> Dict:
        """
        Looks up IP reputation score (0-100) and threat category.
        """
        # Local loopback / private network safe bypass
        if ip_address in ("127.0.0.1", "::1", "localhost") or ip_address.startswith("192.168.") or ip_address.startswith("10."):
            return {"threat_score": 0.0, "category": "Internal/Local IP", "reasons": []}

        if ip_address in self.ip_cache:
            cached = self.ip_cache[ip_address]
            return {
                "threat_score": cached["score"],
                "category": cached["category"],
                "reasons": [f"IP flagged by Threat Intelligence: {cached['category']} (Reputation Score={cached['score']})"]
            }

        # Optional live AbuseIPDB lookup if configured
        api_key = Config.ABUSEIPDB_API_KEY
        if api_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": api_key, "Accept": "application/json"}
                params = {"ipAddress": ip_address, "maxAgeInDays": 30}
                res = requests.get(url, headers=headers, params=params, timeout=2.0)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0))
                    cat = "AbuseIPDB Flagged IP" if score > 30 else "Clean"
                    self.ip_cache[ip_address] = {"score": score, "category": cat}
                    if score > 0:
                        return {
                            "threat_score": score,
                            "category": cat,
                            "reasons": [f"AbuseIPDB confidence score: {score}%"]
                        }
            except Exception:
                pass

        # Default clean
        self.ip_cache[ip_address] = {"score": 0.0, "category": "Clean"}
        return {"threat_score": 0.0, "category": "Clean", "reasons": []}
