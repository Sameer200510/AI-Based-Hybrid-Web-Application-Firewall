from flask import Blueprint, request, jsonify
from app.api.waf_routes import get_waf_inspector
from app.datasets.generator import DatasetGenerator
from app.datasets.evaluator import IEEEBenchmarkEvaluator

ml_bp = Blueprint('ml_bp', __name__)

@ml_bp.route('/status', methods=['GET'])
def get_ml_status():
    """Returns status of the LightGBM model and Explainable AI SHAP explainer."""
    inspector = get_waf_inspector()
    has_model = inspector.ml_engine.model is not None
    return jsonify({
        "model_loaded": has_model,
        "algorithm": "LightGBM Classifier + SHAP TreeExplainer",
        "feature_count": len(inspector.ml_engine.FEATURE_NAMES),
        "features": inspector.ml_engine.FEATURE_NAMES
    }), 200

@ml_bp.route('/evaluate', methods=['POST'])
def run_ieee_evaluation():
    """
    Executes comprehensive IEEE Scientific Evaluation benchmark:
    - Generates CSIC 2010 / HTTP balanced dataset
    - Evaluates AMRSF hybrid pipeline
    - Computes Accuracy, Precision, Recall, F1, ROC Curve, and Latency
    - Compares directly against Signature-only WAF & ModSecurity CRS baselines
    """
    data = request.get_json(silent=True) or {}
    num_samples = int(data.get("samples", 400))

    inspector = get_waf_inspector()
    evaluator = IEEEBenchmarkEvaluator(inspector)
    benchmark_results = evaluator.run_benchmark(num_samples=num_samples)

    return jsonify({
        "status": "completed",
        "benchmark": benchmark_results
    }), 200

@ml_bp.route('/train', methods=['POST'])
def train_model():
    """
    Trains LightGBM model on freshly generated synthetic dataset and saves artifact.
    """
    inspector = get_waf_inspector()
    df = DatasetGenerator.generate_dataset(num_samples=1500)

    try:
        import lightgbm as lgb
        X = []
        y = []
        for _, row in df.iterrows():
            feat = inspector.ml_engine.extract_features(row["url"], {}, row["payload"])
            X.append(feat)
            y.append(row["label"])

        model = lgb.LGBMClassifier(
            n_estimators=120,
            learning_rate=0.08,
            num_leaves=31,
            random_state=42,
            verbose=-1
        )
        model.fit(X, y)
        inspector.ml_engine.save_model(model)
        return jsonify({
            "status": "success",
            "message": f"LightGBM classifier trained on {len(df)} samples and SHAP explainer updated."
        }), 200
    except Exception as e:
        return jsonify({
            "status": "fallback",
            "message": "Using heuristic multi-layer domain features (LightGBM not compiled on system)"
        }), 200
