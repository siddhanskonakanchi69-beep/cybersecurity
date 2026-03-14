import os
import json
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import time

# Get absolute path of the current file
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# models folder inside ml_models
MODEL_DIR = os.path.join(BASE_DIR, "models")

print("Loading models from:", MODEL_DIR)

iso = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
rf = joblib.load(os.path.join(MODEL_DIR, "random_forest.pkl"))
gb = joblib.load(os.path.join(MODEL_DIR, "gradient_boost.pkl"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

with open(os.path.join(MODEL_DIR, "feature_columns.json")) as f:
    feature_columns = json.load(f)

with open(os.path.join(MODEL_DIR, "stats.json")) as f:
    stats = json.load(f)

print("All models loaded successfully")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FeatureRequest(BaseModel):
    features: dict


class BatchRequest(BaseModel):
    samples: list


def preprocess(features):
    df = pd.DataFrame([features])
    df = pd.get_dummies(df)

    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[feature_columns]
    X = scaler.transform(df)

    return X


def derive_severity(threat_class, is_anomaly, binary_pred, confidence):
    # Rule 1: Both models agree it's a critical threat
    if threat_class == "dos" and binary_pred == "attack":
        return "CRITICAL"

    # Rule 2: Specific high-risk attacks
    if threat_class == "u2r":
        return "CRITICAL"
    if threat_class == "r2l" and confidence > 0.8:
        return "HIGH"
    if threat_class == "probe":
        return "MEDIUM"

    # Rule 3: Anomaly + Attack = High Risk
    if is_anomaly and binary_pred == "attack":
        return "HIGH"

    # ---> THE FIX: Add a safety net for high-confidence binary attacks <---
    if binary_pred == "attack" and confidence > 0.90:
        return "HIGH"
    if binary_pred == "attack" and confidence > 0.60:
        return "MEDIUM"

    # Rule 4: Suspicious but not explicitly an attack
    if is_anomaly and binary_pred == "normal":
        return "LOW"

    return "NONE"


@app.get("/health")
def health():
    return {
        "status": "ok",
        "models_loaded": True,
        "timestamp": int(time.time())
    }


@app.get("/model_stats")
def model_stats():
    return stats


@app.post("/predict")
def predict(req: FeatureRequest):
    try:
        X = preprocess(req.features)

        anomaly_score = iso.decision_function(X)[0]
        is_anomaly = anomaly_score < -0.1

        threat_class = rf.predict(X)[0]

        rf_probs = rf.predict_proba(X)[0]
        classes = rf.classes_
        threat_probs = dict(zip(classes, rf_probs))

        binary_pred = gb.predict(X)[0]
        binary_prob = gb.predict_proba(X)[0]

        binary_label = "attack" if binary_pred == 1 else "normal"
        confidence = float(max(binary_prob))

        severity = derive_severity(
            threat_class,
            is_anomaly,
            binary_label,
            confidence
        )

        return {
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(is_anomaly),
            "threat_class": str(threat_class),
            "threat_class_probabilities": {str(k): float(v) for k, v in threat_probs.items()},
            "binary_prediction": binary_label,
            "binary_confidence": confidence,
            "overall_severity": severity
        }

    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/predict_batch")
def predict_batch(req: BatchRequest):
    if len(req.samples) > 100:
        raise HTTPException(status_code=400, detail="Batch limit is 100")

    results = []
    for sample in req.samples:
        res = predict(FeatureRequest(features=sample))
        results.append(res)

    return results