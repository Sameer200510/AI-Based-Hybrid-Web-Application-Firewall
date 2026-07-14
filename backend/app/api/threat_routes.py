from flask import Blueprint, request, jsonify
from app.api.waf_routes import get_waf_inspector
from app.models import ThreatIP

threat_bp = Blueprint('threat_bp', __name__)

@threat_bp.route('/lookup', methods=['GET'])
def lookup_ip_reputation():
    """Queries an IP address against cached/live Threat Intelligence feeds."""
    ip = request.args.get('ip', '198.51.100.24')
    inspector = get_waf_inspector()
    result = inspector.threat_intel.lookup_ip(ip)
    return jsonify({"ip_address": ip, "reputation": result}), 200
