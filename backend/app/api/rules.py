from flask import Blueprint, request, jsonify
from app.database import db
from app.models import WAFRule
from app.api.waf_routes import get_waf_inspector

rules_bp = Blueprint('rules_bp', __name__)

@rules_bp.route('', methods=['GET'])
def get_rules():
    """Lists all active custom signature rules and AMRSF auto-suggested rules."""
    rules = WAFRule.query.order_by(WAFRule.created_at.desc()).all()
    return jsonify({"rules": [r.to_dict() for r in rules]}), 200

@rules_bp.route('', methods=['POST'])
def create_rule():
    """Creates a new custom regex rule and immediately reloads WAF engine."""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    pattern = data.get("pattern", "").strip()
    category = data.get("attack_category", "Custom Signature")
    severity = float(data.get("severity_score", 85.0))

    if not name or not pattern:
        return jsonify({"error": "Rule name and regex pattern are required"}), 400

    rule = WAFRule(
        name=name,
        attack_category=category,
        pattern=pattern,
        severity_score=severity,
        is_active=True,
        is_auto_suggested=False
    )
    db.session.add(rule)
    db.session.commit()

    # Reload active rules in inspector
    active_rules = [r.to_dict() for r in WAFRule.query.filter_by(is_active=True).all()]
    get_waf_inspector().reload_rules(active_rules)

    return jsonify({"status": "created", "rule": rule.to_dict()}), 201

@rules_bp.route('/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule(rule_id):
    """Enables or disables a rule."""
    rule = WAFRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()

    active_rules = [r.to_dict() for r in WAFRule.query.filter_by(is_active=True).all()]
    get_waf_inspector().reload_rules(active_rules)

    return jsonify({"status": "updated", "rule": rule.to_dict()}), 200

@rules_bp.route('/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Deletes a rule."""
    rule = WAFRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()

    active_rules = [r.to_dict() for r in WAFRule.query.filter_by(is_active=True).all()]
    get_waf_inspector().reload_rules(active_rules)

    return jsonify({"status": "deleted"}), 200
