from flask import Blueprint, request, jsonify
from app.models import RequestLog

logs_bp = Blueprint('logs_bp', __name__)

@logs_bp.route('', methods=['GET'])
def get_logs():
    """
    Returns paginated WAF audit logs with full multi-layer score breakdowns
    and Explainable AI SHAP feature attributions.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    decision = request.args.get('decision', None)
    category = request.args.get('category', None)
    ip_query = request.args.get('ip', None)

    query = RequestLog.query
    if decision and decision != 'All':
        query = query.filter(RequestLog.decision == decision)
    if category and category != 'All':
        query = query.filter(RequestLog.attack_category == category)
    if ip_query:
        query = query.filter(RequestLog.ip_address.ilike(f"%{ip_query}%"))

    pagination = query.order_by(RequestLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "logs": [item.to_dict() for item in pagination.items]
    }), 200

@logs_bp.route('/<int:log_id>', methods=['GET'])
def get_log_detail(log_id):
    """Returns single detailed inspection log with exact SHAP tree explanation values."""
    log_entry = RequestLog.query.get_or_404(log_id)
    return jsonify({"log": log_entry.to_dict()}), 200
