import os
from flask import Flask, jsonify
try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False
from app.config import Config
from app.database import db
from app.models import WAFRule

from app.api.waf_routes import waf_bp, get_waf_inspector
from app.api.dashboard import dashboard_bp
from app.api.logs import logs_bp
from app.api.rules import rules_bp
from app.api.ml_routes import ml_bp
from app.api.threat_routes import threat_bp
def create_app():
    """Application factory for AMRSF Web Application Firewall."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if HAS_CORS:
        CORS(app, resources={r"/api/*": {"origins": "*"}})
    else:
        @app.after_request
        def add_cors_headers(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
            return response

    db.init_app(app)

    # Register Blueprints
    app.register_blueprint(waf_bp, url_prefix='/api/v1/waf')
    app.register_blueprint(dashboard_bp, url_prefix='/api/v1/dashboard')
    app.register_blueprint(logs_bp, url_prefix='/api/v1/logs')
    app.register_blueprint(rules_bp, url_prefix='/api/v1/rules')
    app.register_blueprint(ml_bp, url_prefix='/api/v1/ml')
    app.register_blueprint(threat_bp, url_prefix='/api/v1/threat-intel')

    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "AMRSF WAF Research API",
            "version": "1.0.0"
        }), 200

    with app.app_context():
        db.create_all()
        # Seed sample custom rules if empty
        if WAFRule.query.count() == 0:
            sample_rules = [
                WAFRule(
                    name="Block Log4j JNDI Exploits",
                    attack_category="Command Injection",
                    pattern=r"(?i)\$\{\s*jndi\s*:\s*(ldap|rmi|dns|http)",
                    severity_score=98.0,
                    is_active=True
                ),
                WAFRule(
                    name="Block Sensitive AWS/GCP Metadata Query",
                    attack_category="Path Traversal",
                    pattern=r"(?i)169\.254\.169\.254",
                    severity_score=95.0,
                    is_active=True
                )
            ]
            for r in sample_rules:
                db.session.add(r)
            db.session.commit()

            # Load active rules into inspector
            active_rules = [r.to_dict() for r in WAFRule.query.filter_by(is_active=True).all()]
            get_waf_inspector().reload_rules(active_rules)

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    print(f"[+] AMRSF Web Application Firewall API starting on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
