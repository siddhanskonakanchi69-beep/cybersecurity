import os
import json
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, accuracy_score, roc_auc_score
from imblearn.over_sampling import SMOTE

from feature_engineering import prepare_features

# Create foolproof absolute paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

(
    X_train,
    X_test,
    y_binary_train,
    y_binary_test,
    y_multiclass_train,
    y_multiclass_test,
    feature_columns,
    scaler
) = prepare_features()

print("=== DATA LOADED ===")
print("Train shape:", X_train.shape)
print("Test shape:", X_test.shape)

# =========================
# MODEL 1 — IsolationForest
# =========================

print("\n=== TRAINING ISOLATION FOREST ===")

normal_idx = np.where(y_binary_train == 0)[0]
X_train_normal = X_train[normal_idx]

iso = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

iso.fit(X_train_normal)

scores = iso.decision_function(X_test)
preds = (scores < -0.1).astype(int)

iso_precision = precision_score(y_binary_test, preds)
iso_recall = recall_score(y_binary_test, preds)
iso_f1 = f1_score(y_binary_test, preds)

print("Precision:", iso_precision)
print("Recall:", iso_recall)
print("F1:", iso_f1)

joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))

# =========================
# MODEL 2 — RandomForest (WITH SMOTE)
# =========================

print("\n=== TRAINING RANDOM FOREST ===")
print("Applying SMOTE to balance multiclass data. This might take a minute...")

smote = SMOTE(random_state=42)
X_train_smote, y_multiclass_train_smote = smote.fit_resample(X_train, y_multiclass_train)

print(f"SMOTE complete! Original train size: {len(X_train)} | New train size: {len(X_train_smote)}")

rf = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train_smote, y_multiclass_train_smote)

rf_preds = rf.predict(X_test)

print("\nClassification Report")
print(classification_report(y_multiclass_test, rf_preds))

print("\nConfusion Matrix")
print(confusion_matrix(y_multiclass_test, rf_preds))

rf_accuracy = accuracy_score(y_multiclass_test, rf_preds)

importances = rf.feature_importances_
indices = np.argsort(importances)[::-1]

print("\nTop 15 Important Features")

top_features = []

for i in range(15):
    fname = feature_columns[indices[i]]
    score = float(importances[indices[i]])
    print(f"{i+1}. {fname} ({score:.4f})")

    top_features.append({
        "feature": fname,
        "importance": score
    })

joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))

# =========================
# MODEL 3 — GradientBoost
# =========================

print("\n=== TRAINING GRADIENT BOOST ===")

gb = GradientBoostingClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    random_state=42
)

gb.fit(X_train, y_binary_train)

gb_preds = gb.predict(X_test)
gb_probs = gb.predict_proba(X_test)[:, 1]

gb_accuracy = accuracy_score(y_binary_test, gb_preds)
gb_precision = precision_score(y_binary_test, gb_preds)
gb_recall = recall_score(y_binary_test, gb_preds)
gb_f1 = f1_score(y_binary_test, gb_preds)
gb_auc = roc_auc_score(y_binary_test, gb_probs)

print("\nGradientBoost Metrics")
print("Accuracy:", gb_accuracy)
print("Precision:", gb_precision)
print("Recall:", gb_recall)
print("F1:", gb_f1)
print("ROC-AUC:", gb_auc)

joblib.dump(gb, os.path.join(MODEL_DIR, "gradient_boost.pkl"))

# =========================
# SUMMARY & SAVE EVERYTHING
# =========================

print("\n=== MODEL PERFORMANCE SUMMARY ===")
print(f"IsolationForest    | Precision: {iso_precision:.3f} | Recall: {iso_recall:.3f} | F1: {iso_f1:.3f}")
print(f"RandomForest       | Accuracy: {rf_accuracy:.3f}")
print(f"GradientBoost      | Accuracy: {gb_accuracy:.3f} | ROC-AUC: {gb_auc:.3f}")
print("=================================")

joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
with open(os.path.join(MODEL_DIR, "feature_columns.json"), "w") as f:
    json.dump(list(feature_columns), f)

stats = {
    "isolation_forest": {
        "precision": float(iso_precision),
        "recall": float(iso_recall),
        "f1": float(iso_f1)
    },
    "random_forest": {
        "accuracy": float(rf_accuracy),
        "top_features": top_features[:10]
    },
    "gradient_boost": {
        "accuracy": float(gb_accuracy),
        "precision": float(gb_precision),
        "recall": float(gb_recall),
        "f1": float(gb_f1),
        "roc_auc": float(gb_auc)
    }
}

with open(os.path.join(MODEL_DIR, "stats.json"), "w") as f:
    json.dump(stats, f, indent=2)

print("\nSaved all models, prep files, and stats.json")