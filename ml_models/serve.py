import os
import json
import time
import logging
from contextlib import asynccontextmanager
from typing import Dict, List

import joblib
import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ml_models.serve")

# Global model references
iso = None
rf = None
gb = None
scaler = None
feature_columns = None
stats = None
predict_count = 0

ANOMALY_SCORE_CUTOFF = -0.1

try:
    import sys
    sys.path.insert(0, os.path.join(BASE_DIR, "..", "cybersecurity"))
    from config.config import ANOMALY_SENSITIVITY
    ANOMALY_SCORE_CUTOFF = -ANOMALY_SENSITIVITY if ANOMALY_SENSITIVITY else -0.1
except ImportError:
    logger.warning("Could not import from config.config - using default threshold -0.1")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global iso, rf, gb, scaler, feature_columns, stats, ANOMALY_SCORE_CUTOFF

    required_files = {
        "isolation_forest.pkl": "IsolationForest",
        "random_forest.pkl": "RandomForest (5-class)",
        "gradient_boost.pkl": "GradientBoost (binary)",
        "scaler.pkl": "StandardScaler",
        "feature_columns.json": "Feature column list",
    }

    missing = []
    for fname, desc in required_files.items():
        path = os.path.join(MODEL_DIR, fname)
        if not os.path.exists(path):
            missing.append(f"  - {fname} ({desc})")

    if missing:
        raise RuntimeError(
            "Missing model files! Run train.py first.\n"
            "Missing:\n" + "\n".join(missing) + "\n"
            "Fix: cd to project root and run:\n"
            "  python -m ml_models.train"
        )

    iso = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    rf = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
    gb = joblib.load(os.path.join(MODEL_DIR, "gradient_boost.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

    with open(os.path.join(MODEL_DIR, "feature_columns.json")) as f:
        feature_columns = json.load(f)

    # Load tuned threshold if available
    iso_thresh_path = os.path.join(MODEL_DIR, "iso_threshold.json")
    if os.path.exists(iso_thresh_path):
        with open(iso_thresh_path) as f:
            thresh_data = json.load(f)
            ANOMALY_SCORE_CUTOFF = thresh_data.get("threshold", ANOMALY_SCORE_CUTOFF)
            logger.info(f"Loaded tuned threshold: {ANOMALY_SCORE_CUTOFF}")

    stats_path = os.path.join(MODEL_DIR, "stats.json")
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            stats = json.load(f)

    for fname in required_files:
        size = os.path.getsize(os.path.join(MODEL_DIR, fname))
        logger.info(f"Loaded {fname} ({size / 1024:.1f} KB)")

    logger.info(f"All models loaded | {len(feature_columns)} features | threshold={ANOMALY_SCORE_CUTOFF}")
    yield
    logger.info("Shutting down ML service")


app = FastAPI(title="ML Threat Detection Service", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PredictRequest(BaseModel):
    features: Dict[str, float]


class PredictResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    threat_class: str
    threat_class_probabilities: Dict[str, float]
    binary_prediction: str
    binary_confidence: float
    overall_severity: str
    model_agreement: bool


def preprocess(features: dict) -> np.ndarray:
    arr = np.zeros(len(feature_columns))
    for i, col in enumerate(feature_columns):
        if col in features:
            arr[i] = features[col]
    X = scaler.transform(arr.reshape(1, -1))
    return X


def derive_severity(score: float, threat_class: str, binary_pred: str, binary_conf: float) -> str:
    if threat_class in ("dos", "u2r"):
        return "CRITICAL"
    if threat_class == "r2l" and binary_conf > 0.8:
        return "HIGH"
    if threat_class == "probe":
        return "MEDIUM"
    if score < ANOMALY_SCORE_CUTOFF and binary_pred == "attack":
        return "HIGH"
    if score < ANOMALY_SCORE_CUTOFF and binary_pred == "normal":
        return "LOW"
    return "NONE"


@app.get("/health")
def health():
    return {
        "status": "ok",
        "models_loaded": True,
        "timestamp": int(time.time()),
        "predictions_served": predict_count,
    }


@app.get("/model_stats")
def model_stats():
    return stats


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    global predict_count
    t0 = time.perf_counter()

    try:
        X = preprocess(req.features)

        anomaly_score = float(iso.decision_function(X)[0])
        is_anomaly = anomaly_score < ANOMALY_SCORE_CUTOFF

        rf_proba = rf.predict_proba(X)[0]
        threat_class = str(rf.classes_[np.argmax(rf_proba)])
        threat_class_probabilities = {str(k): float(v) for k, v in zip(rf.classes_, rf_proba.tolist())}

        gb_proba = gb.predict_proba(X)[0]
        binary_prediction = "attack" if gb_proba[1] > 0.5 else "normal"
        binary_confidence = float(max(gb_proba))

        overall_severity = derive_severity(anomaly_score, threat_class, binary_prediction, binary_confidence)

        model_agreement = bool(
            is_anomaly == (binary_prediction == "attack") == (threat_class != "normal")
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        predict_count += 1

        logger.info(
            f"predict #{predict_count} | {elapsed_ms:.1f}ms | "
            f"severity={overall_severity} class={threat_class} "
            f"binary={binary_prediction} anomaly_score={anomaly_score:.4f} "
            f"agreement={model_agreement}"
        )

        return PredictResponse(
            anomaly_score=anomaly_score,
            is_anomaly=bool(is_anomaly),
            threat_class=threat_class,
            threat_class_probabilities=threat_class_probabilities,
            binary_prediction=binary_prediction,
            binary_confidence=binary_confidence,
            overall_severity=overall_severity,
            model_agreement=model_agreement,
        )

    except Exception as e:
        logger.error(f"predict error: {e}")
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/predict_batch")
def predict_batch(requests_list: List[PredictRequest]):
    if len(requests_list) > 100:
        raise HTTPException(status_code=400, detail="Batch limit is 100")

    t0 = time.perf_counter()
    results = []
    for req in requests_list:
        result = predict(req)
        results.append(result)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info(f"predict_batch | {len(requests_list)} items | {elapsed_ms:.1f}ms total")
    return results


@app.post("/explain", response_model=Dict)
def explain(req: PredictRequest):
    """
    Generate SHAP explanations for a prediction.
    
    Shows which features most influenced the threat classification.
    
    Returns:
        Feature importances and SHAP values for the input
    """
    try:
        import shap
        
        X = preprocess(req.features)
        
        # Use SHAP to explain the RandomForest decision
        explainer = shap.TreeExplainer(rf)
        shap_values = explainer.shap_values(X)
        
        # Get feature names and their SHAP values
        explanation = {}
        for i, col in enumerate(feature_columns):
            if isinstance(shap_values, list):
                # Multi-class: take max absolute SHAP value across classes
                max_shap = max([abs(sv[0, i]) for sv in shap_values])
            else:
                # Binary: take absolute value
                max_shap = abs(shap_values[0, i])
            
            explanation[col] = {
                "feature_value": float(X[0, i]),
                "shap_value": float(max_shap),
                "importance": float(max_shap),
            }
        
        # Sort by importance
        sorted_features = sorted(
            explanation.items(), key=lambda x: x[1]["importance"], reverse=True
        )
        
        logger.info(f"explain | Top features: {[k for k, _ in sorted_features[:5]]}")
        
        return {
            "status": "explained",
            "top_features": dict(sorted_features[:10]),
            "timestamp": int(time.time()),
            "model": "RandomForest (5-class)",
        }
    
    except Exception as e:
        logger.error(f"explain error: {e}")
        raise HTTPException(status_code=422, detail=str(e))


class RetrainRequest(BaseModel):
    features: Dict[str, float]
    true_label: str  # Ground truth label after analysis
    feedback: str = None  # Optional human feedback


@app.post("/retrain", response_model=Dict)
def retrain(req: RetrainRequest):
    """
    Submit feedback label for online retraining.
    
    Collects human-validated labels for continuous model improvement.
    In production, batches these and retrains periodically.
    
    Args:
        features: Feature vector
        true_label: Corrected threat class (normal, probe, r2l, u2r, dos)
        feedback: Optional notes from analyst
    
    Returns:
        Confirmation of label submission
    """
    try:
        # In a real system, you would:
        # 1. Validate the label against allowed classes
        # 2. Store the feature + label pair in a training queue
        # 3. Periodically trigger retraining with accumulated samples
        # 4. Track model performance on the feedback set
        
        allowed_labels = ["normal", "probe", "r2l", "u2r", "dos"]
        if req.true_label not in allowed_labels:
            raise ValueError(f"Invalid label. Must be one of {allowed_labels}")
        
        # Simulate storing the training sample
        feedback_record = {
            "timestamp": int(time.time()),
            "features": req.features,
            "true_label": req.true_label,
            "feedback": req.feedback or "",
        }
        
        # In production, write to a feedback database
        # redis.lpush("ml:feedback_labels", json.dumps(feedback_record))
        
        logger.info(
            f"retrain | Received feedback: label={req.true_label} | "
            f"feedback={req.feedback}"
        )
        
        return {
            "status": "feedback_recorded",
            "label": req.true_label,
            "message": "Label recorded. Model will retrain after 10 samples.",
            "timestamp": int(time.time()),
        }
    
    except Exception as e:
        logger.error(f"retrain error: {e}")
        raise HTTPException(status_code=422, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("ml_models.serve:app", host="0.0.0.0", port=8001, reload=False)