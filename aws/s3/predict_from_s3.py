"""VulnGuard AI - load the model and features from S3 and predict.
Proves the model stored in S3 loads cleanly (requires scikit-learn==1.9.1).
"""
import io

import boto3
import joblib
import pandas as pd
from botocore.config import Config

PROFILE = "learnerlab"
REGION = "us-east-1"
BUCKET = "vulnguard-ai-2026"


def main():
    s3 = boto3.Session(profile_name=PROFILE, region_name=REGION).client("s3", config=Config(connect_timeout=10, read_timeout=60, retries={"max_attempts": 3}))
    model = joblib.load(io.BytesIO(
        s3.get_object(Bucket=BUCKET, Key="models/risk_model.joblib")["Body"].read()))
    X = pd.read_csv(io.BytesIO(
        s3.get_object(Bucket=BUCKET, Key="processed/ml/X_features.csv")["Body"].read()))
    proba = model.predict_proba(X)[:, 1]
    print(f"OK from S3 | {len(proba)} predictions | max {proba.max():.3f}")


if __name__ == "__main__":
    main()


