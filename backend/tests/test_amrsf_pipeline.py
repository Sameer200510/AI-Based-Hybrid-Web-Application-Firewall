import json
import pytest
from app.waf_engine.signatures import SignatureEngine
from app.waf_engine.decoder import RecursiveDecoderEngine
from app.waf_engine.complexity import ComplexityAnalyzer
from app.waf_engine.ml_engine import ExplainableMLEngine
from app.waf_engine.scoring import AdaptiveRiskScorer
from app.waf_engine.inspector import WAFInspector
from run import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_signature_detection():
    sig = SignatureEngine()
    # SQLi test
    res_sqli = sig.inspect("/products?id=1 UNION SELECT 1,username,password FROM users--", {}, "")
    assert res_sqli["signature_score"] >= 90.0
    assert "SQL Injection" in res_sqli["primary_category"]

    # XSS test
    res_xss = sig.inspect("/comment", {}, "<script>alert(1)</script>")
    assert res_xss["signature_score"] >= 90.0
    assert "XSS" in res_xss["primary_category"]

    # Command Injection test
    res_cmd = sig.inspect("/ping?host=127.0.0.1; cat /etc/passwd", {}, "")
    assert res_cmd["signature_score"] >= 90.0
    assert "Command Injection" in res_cmd["primary_category"]

def test_recursive_decoder():
    decoder = RecursiveDecoderEngine()
    # Double URL encoding of single quote %2527 -> %27 -> '
    res = decoder.decode_payload("%2527%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54")
    assert "UNION SELECT" in res["decoded_payload"]
    assert res["encoding_depth"] >= 1

def test_complexity_analyzer():
    comp = ComplexityAnalyzer()
    res_normal = comp.analyze("/home", "page=1")
    assert res_normal["complexity_score"] == 0.0

    res_entropy = comp.analyze("/search", "payload=" + ("A@9$k#L!xZ&P*qW~" * 5))
    assert res_entropy["shannon_entropy"] > 3.8

def test_ml_and_shap_explainer():
    ml = ExplainableMLEngine()
    res = ml.predict_with_shap("/login?u=admin' OR 1=1--", {}, "password=secret")
    assert res["ml_confidence"] > 0.0
    assert isinstance(res["shap_explanations"], list)

def test_adaptive_risk_scorer():
    scorer = AdaptiveRiskScorer()
    res_allow = scorer.calculate_final_score({"signature_score": 0.0, "ml_confidence": 10.0})
    assert res_allow["decision"] == "Allow"

    res_block = scorer.calculate_final_score({"signature_score": 95.0, "ml_confidence": 92.0})
    assert res_block["decision"] == "Block"
    assert res_block["final_risk_score"] >= 76.0

def test_full_pipeline_inspection(client):
    response = client.post('/api/v1/waf/inspect', json={
        "ip_address": "198.51.100.24",
        "method": "GET",
        "url": "/api/v1/users?id=1' UNION SELECT 1,admin,pass FROM users--",
        "headers": {"User-Agent": "PyTest-Security-Lab"},
        "payload": ""
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["inspection_result"]["decision"] == "Block"
    assert data["inspection_result"]["final_risk_score"] >= 76.0

def test_dashboard_stats(client):
    response = client.get('/api/v1/dashboard/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert "total_requests" in data
    assert "risk_distribution" in data
