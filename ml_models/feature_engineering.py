import pandas as pd
import json
import joblib
import os
from sklearn.preprocessing import StandardScaler

DATA_DIR = "ml_models/data"
MODEL_DIR = "ml_models/models"

os.makedirs(MODEL_DIR, exist_ok=True)

train_path = os.path.join(DATA_DIR, "train_clean.csv")
test_path = os.path.join(DATA_DIR, "test_clean.csv")

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)

categorical_cols = ["protocol_type", "service", "flag"]

y_binary_train = train_df["binary_label"]
y_binary_test = test_df["binary_label"]

y_multiclass_train = train_df["attack_class"]
y_multiclass_test = test_df["attack_class"]

X_train = train_df.drop(["label","difficulty_level","binary_label","attack_class"], axis=1)
X_test = test_df.drop(["label","difficulty_level","binary_label","attack_class"], axis=1)

X_train = pd.get_dummies(X_train, columns=categorical_cols)
X_test = pd.get_dummies(X_test, columns=categorical_cols)

X_train, X_test = X_train.align(X_test, join="left", axis=1, fill_value=0)

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

feature_columns = X_train.columns.tolist()

joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

with open(os.path.join(MODEL_DIR, "feature_columns.json"), "w") as f:
    json.dump(feature_columns, f)

print("Feature engineering completed")
print("Train shape:", X_train_scaled.shape)
print("Test shape:", X_test_scaled.shape)

def prepare_features():
    return (
        X_train_scaled,
        X_test_scaled,
        y_binary_train,
        y_binary_test,
        y_multiclass_train,
        y_multiclass_test,
        feature_columns,
        scaler
    )