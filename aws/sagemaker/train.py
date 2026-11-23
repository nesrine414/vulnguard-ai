"""VulnGuard AI - SageMaker training script (KEV risk classifier).
Reads X_features.csv and y_kev.csv from the training channel,
runs stratified CV, trains the final pipeline and saves it to the model dir.
"""
import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

RANDOM_STATE = 42
N_SPLITS = 5


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default=os.environ.get("SM_CHANNEL_TRAIN", "/opt/ml/input/data/train"))
    parser.add_argument("--model-dir", default=os.environ.get("SM_MODEL_DIR", "/opt/ml/model"))
    args = parser.parse_args()

    X = pd.read_csv(os.path.join(args.train, "X_features.csv"))
    y = pd.read_csv(os.path.join(args.train, "y_kev.csv"))["is_kev"].astype(int)
    print(f"Samples: {len(X)}, features: {X.shape[1]}, KEV: {int(y.sum())}")

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100, max_depth=6, class_weight="balanced",
            random_state=RANDOM_STATE, n_jobs=-1)),
    ])

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_validate(
        pipeline, X, y, cv=cv,
        scoring=["roc_auc", "average_precision", "f1", "recall", "precision"],
    )
    metrics = {
        "roc_auc_mean": round(float(scores["test_roc_auc"].mean()), 4),
        "pr_auc_mean": round(float(scores["test_average_precision"].mean()), 4),
        "f1_mean": round(float(scores["test_f1"].mean()), 4),
        "recall_mean": round(float(scores["test_recall"].mean()), 4),
        "precision_mean": round(float(scores["test_precision"].mean()), 4),
    }
    print("CV metrics:", json.dumps(metrics))

    pipeline.fit(X, y)
    os.makedirs(args.model_dir, exist_ok=True)
    joblib.dump(pipeline, os.path.join(args.model_dir, "risk_model.joblib"))

    metadata = {
        "model_name": "VulnGuard KEV Risk Classifier",
        "algorithm": "RandomForestClassifier(balanced)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trained_on": "AWS SageMaker",
        "total_samples": len(X),
        "total_features": X.shape[1],
        "feature_names": list(X.columns),
        "evaluation_metrics": metrics,
    }
    with open(os.path.join(args.model_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print("Model saved.")


if __name__ == "__main__":
    main()
