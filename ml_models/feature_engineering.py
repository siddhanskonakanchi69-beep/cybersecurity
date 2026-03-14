import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODEL_DIR, exist_ok=True)


def prepare_features(train_df, test_df):
    """
    One-hot encode categoricals, align columns, scale features.

    Returns:
        (X_train_scaled, X_test_scaled,
         y_bin_train, y_bin_test,
         y_5_train, y_5_test,
         feature_columns, scaler)
    """
    categorical_cols = ["protocol_type", "service", "flag"]

    y_bin_train = train_df["label_binary"]
    y_bin_test = test_df["label_binary"]
    y_5_train = train_df["label_5class"]
    y_5_test = test_df["label_5class"]

    drop_cols = ["label", "difficulty_level", "label_binary", "label_5class"]
    X_train = train_df.drop(columns=drop_cols)
    X_test = test_df.drop(columns=drop_cols)

    X_train_enc = pd.get_dummies(X_train, columns=categorical_cols)
    X_test_enc = pd.get_dummies(X_test, columns=categorical_cols)

    X_train_enc, X_test_enc = X_train_enc.align(
        X_test_enc, join="left", axis=1, fill_value=0
    )

    feature_columns = X_train_enc.columns.tolist()

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_enc)
    X_test_scaled = scaler.transform(X_test_enc)

    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    with open(os.path.join(MODEL_DIR, "feature_columns.json"), "w") as f:
        json.dump(feature_columns, f)

    print(f"  Feature columns: {len(feature_columns)}")
    print(f"  X_train_scaled shape: {X_train_scaled.shape}")
    print(f"  X_test_scaled  shape: {X_test_scaled.shape}")

    return (
        X_train_scaled,
        X_test_scaled,
        y_bin_train,
        y_bin_test,
        y_5_train,
        y_5_test,
        feature_columns,
        scaler,
    )


if __name__ == "__main__":
    train_df = pd.read_csv(os.path.join(DATA_DIR, "train_clean.csv"))
    test_df = pd.read_csv(os.path.join(DATA_DIR, "test_clean.csv"))

    result = prepare_features(train_df, test_df)
    print("\n[OK] feature_engineering.py complete!")
    print(f"  Saved scaler.pkl and feature_columns.json to {MODEL_DIR}")