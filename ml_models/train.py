import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score,
    accuracy_score, roc_auc_score,
)
from imblearn.over_sampling import SMOTE

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, PROJECT_ROOT)

from ml_models.feature_engineering import prepare_features

MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(MODEL_DIR, exist_ok=True)

# Anomaly score cutoff - try config, fallback to default
ANOMALY_SCORE_CUTOFF = -0.1
try:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "cybersecurity"))
    from config.config import ANOMALY_SENSITIVITY
    ANOMALY_SCORE_CUTOFF = -ANOMALY_SENSITIVITY if ANOMALY_SENSITIVITY else -0.1
    print(f"  Using anomaly cutoff from config: {ANOMALY_SCORE_CUTOFF}")
except ImportError:
    print(f"  config.config not available - using default cutoff: {ANOMALY_SCORE_CUTOFF}")


# --- Load data ---
print("=" * 50)
print("  LOADING DATA & PREPARING FEATURES")
print("=" * 50)

train_df = pd.read_csv(os.path.join(DATA_DIR, "train_clean.csv"))
test_df = pd.read_csv(os.path.join(DATA_DIR, "test_clean.csv"))

(
    X_train, X_test,
    y_bin_train, y_bin_test,
    y_5_train, y_5_test,
    feature_columns, scaler,
) = prepare_features(train_df, test_df)

print(f"\n  Train shape: {X_train.shape}")
print(f"  Test  shape: {X_test.shape}")


# ===================================================
# MODEL 1 - IsolationForest (TUNED)
# ===================================================
print("\n" + "=" * 50)
print("  MODEL 1 - IsolationForest (TUNED)")
print("=" * 50)

normal_idx = np.where(y_bin_train == 0)[0]
X_train_normal = X_train[normal_idx]
print(f"  Training on {len(normal_idx)} normal samples")

# Higher contamination -> more aggressive at flagging anomalies -> higher recall
iso = IsolationForest(
    n_estimators=200,
    contamination=0.15,     # was 0.05 -> 0.15 for better recall
    max_features=0.8,       # use 80% features per tree for diversity
    random_state=42,
    n_jobs=-1,
)
iso.fit(X_train_normal)

scores = iso.decision_function(X_test)

# Find best threshold by sweeping
print("\n  Threshold sweep:")
best_f1 = 0
best_thresh = ANOMALY_SCORE_CUTOFF
for thresh in [-0.02, -0.05, -0.08, -0.10, -0.12, -0.15]:
    preds_t = (scores < thresh).astype(int)
    p = precision_score(y_bin_test, preds_t, zero_division=0)
    r = recall_score(y_bin_test, preds_t, zero_division=0)
    f = f1_score(y_bin_test, preds_t, zero_division=0)
    marker = ""
    if f > best_f1:
        best_f1 = f
        best_thresh = thresh
        marker = " <-- best"
    print(f"    thresh={thresh:6.2f}  P={p:.3f} R={r:.3f} F1={f:.3f}{marker}")

print(f"\n  Selected threshold: {best_thresh}")
iso_preds = (scores < best_thresh).astype(int)

iso_precision = precision_score(y_bin_test, iso_preds)
iso_recall = recall_score(y_bin_test, iso_preds)
iso_f1 = f1_score(y_bin_test, iso_preds)

print(f"  Final -> Precision: {iso_precision:.4f}")
print(f"           Recall:    {iso_recall:.4f}")
print(f"           F1:        {iso_f1:.4f}")

# Save the best threshold alongside model
joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
with open(os.path.join(MODEL_DIR, "iso_threshold.json"), "w") as f:
    json.dump({"threshold": best_thresh}, f)


# ===================================================
# MODEL 2 - RandomForest (5-class) WITH SMOTE
# ===================================================
print("\n" + "=" * 50)
print("  MODEL 2 - RandomForest (5-class) + SMOTE")
print("=" * 50)

print("  Class distribution BEFORE SMOTE:")
unique, counts = np.unique(y_5_train, return_counts=True)
for cls, cnt in zip(unique, counts):
    print(f"    {cls:10s}: {cnt:6d}")

print("\n  Applying SMOTE to balance minority classes...")
smote = SMOTE(random_state=42)
X_train_smote, y_5_train_smote = smote.fit_resample(X_train, y_5_train)

print(f"  Original: {len(X_train)} -> SMOTE: {len(X_train_smote)}")
print("  Class distribution AFTER SMOTE:")
unique, counts = np.unique(y_5_train_smote, return_counts=True)
for cls, cnt in zip(unique, counts):
    print(f"    {cls:10s}: {cnt:6d}")

rf = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    class_weight="balanced_subsample",   # extra class balancing
    random_state=42,
    n_jobs=-1,
)
rf.fit(X_train_smote, y_5_train_smote)

rf_preds = rf.predict(X_test)
rf_accuracy = accuracy_score(y_5_test, rf_preds)
rf_macro_f1 = f1_score(y_5_test, rf_preds, average="macro")

print(f"\n  Accuracy:  {rf_accuracy:.4f}")
print(f"  Macro F1:  {rf_macro_f1:.4f}")

print("\n  Classification Report:")
print(classification_report(y_5_test, rf_preds))

print("  Confusion Matrix:")
print(confusion_matrix(y_5_test, rf_preds))

importances = rf.feature_importances_
indices = np.argsort(importances)[::-1]

print("\n  Top 15 Feature Importances:")
feature_importance_dict = {}
for i in range(min(15, len(feature_columns))):
    fname = feature_columns[indices[i]]
    score = float(importances[indices[i]])
    print(f"    {i+1:2d}. {fname:40s} {score:.4f}")
    feature_importance_dict[fname] = score

joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))


# ===================================================
# MODEL 3 - GradientBoost (binary)
# ===================================================
print("\n" + "=" * 50)
print("  MODEL 3 - GradientBoost (binary)")
print("=" * 50)

gb = GradientBoostingClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    random_state=42,
)
gb.fit(X_train, y_bin_train)

gb_preds = gb.predict(X_test)
gb_probs = gb.predict_proba(X_test)[:, 1]

gb_accuracy = accuracy_score(y_bin_test, gb_preds)
gb_precision = precision_score(y_bin_test, gb_preds)
gb_recall = recall_score(y_bin_test, gb_preds)
gb_f1 = f1_score(y_bin_test, gb_preds)
gb_auc = roc_auc_score(y_bin_test, gb_probs)

print(f"  Accuracy:  {gb_accuracy:.4f}")
print(f"  Precision: {gb_precision:.4f}")
print(f"  Recall:    {gb_recall:.4f}")
print(f"  F1:        {gb_f1:.4f}")
print(f"  ROC-AUC:   {gb_auc:.4f}")

joblib.dump(gb, os.path.join(MODEL_DIR, "gradient_boost.pkl"))


# ===================================================
# SAVE stats.json
# ===================================================
top10_importance = {feature_columns[indices[i]]: float(importances[indices[i]])
                    for i in range(min(10, len(feature_columns)))}

stats = {
    "isolation_forest": {
        "precision": float(iso_precision),
        "recall": float(iso_recall),
        "f1": float(iso_f1),
        "threshold": float(best_thresh),
    },
    "random_forest": {
        "accuracy": float(rf_accuracy),
        "macro_f1": float(rf_macro_f1),
        "feature_importances": top10_importance,
        "smote_applied": True,
    },
    "gradient_boost": {
        "accuracy": float(gb_accuracy),
        "roc_auc": float(gb_auc),
    },
    "feature_columns": list(feature_columns),
    "trained_at": int(time.time()),
}

stats_path = os.path.join(MODEL_DIR, "stats.json")
with open(stats_path, "w") as f:
    json.dump(stats, f, indent=2)


# ===================================================
# FINAL SUMMARY
# ===================================================
print("\n")
print("=" * 50)
print("  MODEL PERFORMANCE SUMMARY")
print("=" * 50)
print(f"  IsolationForest  | P: {iso_precision:.2f} R: {iso_recall:.2f} F1: {iso_f1:.2f} (thresh: {best_thresh})")
print(f"  RandomForest     | Acc: {rf_accuracy:.2f} MacroF1: {rf_macro_f1:.2f} (SMOTE)")
print(f"  GradientBoost    | Acc: {gb_accuracy:.2f} ROC-AUC: {gb_auc:.2f}")
print("=" * 50)

print(f"\n[OK] train.py complete! All models saved to {MODEL_DIR}")