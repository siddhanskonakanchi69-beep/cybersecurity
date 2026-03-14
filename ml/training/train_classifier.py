"""
Threat Classifier Training Script
Trains XGBoost classifier on labeled network/log event features.
Run: python ml/training/train_classifier.py
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import xgboost as xgb
import joblib, os
from loguru import logger

MODEL_PATH = "ml/models/threat_classifier.joblib"
DATA_PATH  = "ml/data/labeled_events.csv"


def load_data(path: str) -> tuple:
    """Load and preprocess labeled event data."""
    df = pd.read_csv(path)
    feature_cols = [
        "packets_per_second", "distinct_ports", "failed_auths",
        "hour_of_day", "bytes_transferred", "connection_duration",
        "protocol_tcp", "protocol_udp", "is_known_bad_ip",
    ]
    X = df[feature_cols].fillna(0)
    le = LabelEncoder()
    y  = le.fit_transform(df["threat_label"])
    return X, y, le


def train():
    logger.info("Loading training data...")
    if not os.path.exists(DATA_PATH):
        logger.warning(f"No data at {DATA_PATH} — generating synthetic sample for dev")
        _generate_synthetic_data(DATA_PATH)

    X, y, le = load_data(DATA_PATH)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info("Training XGBoost classifier...")
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = model.predict(X_test)
    logger.info("\n" + classification_report(y_test, y_pred, target_names=le.classes_))

    os.makedirs("ml/models", exist_ok=True)
    joblib.dump({"model": model, "label_encoder": le}, MODEL_PATH)
    logger.info(f"✅ Model saved to {MODEL_PATH}")


def _generate_synthetic_data(path: str):
    """Generate synthetic labeled data for development."""
    np.random.seed(42)
    n = 5000
    df = pd.DataFrame({
        "packets_per_second":   np.random.exponential(1000, n),
        "distinct_ports":       np.random.randint(1, 100, n),
        "failed_auths":         np.random.randint(0, 50, n),
        "hour_of_day":          np.random.randint(0, 24, n),
        "bytes_transferred":    np.random.exponential(1e6, n),
        "connection_duration":  np.random.exponential(30, n),
        "protocol_tcp":         np.random.randint(0, 2, n),
        "protocol_udp":         np.random.randint(0, 2, n),
        "is_known_bad_ip":      np.random.randint(0, 2, n),
        "threat_label":         np.random.choice(
            ["normal", "dos", "probe", "brute_force", "lateral_movement"], n,
            p=[0.6, 0.1, 0.1, 0.1, 0.1]
        )
    })
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    logger.info(f"Synthetic data written to {path}")


if __name__ == "__main__":
    train()
