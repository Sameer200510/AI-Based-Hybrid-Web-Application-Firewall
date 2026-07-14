# AMRSF Web Application Firewall REST API Documentation

Base URL: `http://localhost:5000/api/v1`

---

## 1. WAF Core Inspection API

### `POST /waf/inspect`
Inspects an incoming HTTP request through all 6 AMRSF layers and returns the multi-layer risk score, automated decision, and Explainable AI (SHAP TreeExplainer) feature attributions.

#### Request Body (JSON)
```json
{
  "ip_address": "198.51.100.24",
  "method": "GET",
  "url": "/api/v1/users?id=1' UNION SELECT 1,username,password FROM admin--",
  "headers": {
    "User-Agent": "Mozilla/5.0 Scanner"
  },
  "payload": ""
}
```

#### Response (200 OK)
```json
{
  "status": "success",
  "log_id": 1042,
  "inspection_result": {
    "final_risk_score": 96.4,
    "decision": "Block",
    "action_taken": "Instant HTTP 403 Forbidden Block & IP Watchlist Quarantine",
    "attack_category": "SQL Injection",
    "reason": "[SQL Injection] SQL Keywords UNION/SELECT/INSERT/DELETE detected | Sql Keyword Count (+36% contribution)",
    "scores_breakdown": {
      "signature_score": 95.0,
      "encoding_suspicion": 0.0,
      "payload_complexity": 25.0,
      "ml_confidence": 98.2,
      "behavioral_score": 0.0,
      "threat_intel_score": 88.0
    },
    "shap_explanations": [
      {
        "feature": "Sql Keyword Count",
        "impact": 0.42,
        "direction": "+",
        "value_observed": 2.0
      }
    ]
  }
}
```

---

## 2. Dashboard Analytics API

### `GET /dashboard/stats`
Returns live Security Operations Center (SOC) KPI metrics, score distribution buckets, top attack categories, top targeted endpoints, and geolocation statistics.

### `GET /dashboard/timeline`
Returns reconstructed multi-stage attack campaigns ordered chronologically.

---

## 3. Rules & Threat Intel API

### `GET /rules`
Lists active signature rules and WAF permanent rule suggestions.

### `POST /rules`
Creates a dynamic signature pattern rule.

### `GET /threat-intel/lookup?ip=198.51.100.24`
Returns cached or live threat reputation score (0-100) for a given IP address.
