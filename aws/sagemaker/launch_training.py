"""VulnGuard AI - launch a SageMaker Training Job (dry-run by default).
Packages aws/sagemaker/train.py, uploads it to the output bucket,
then starts a one-off training job. Use --run to actually launch it.
"""
import argparse
import io
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import boto3

PROFILE = "learnerlab"
REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::992382575404:role/LabRole"
DATA_URI = "s3://vulnguard-ai-2026/processed/ml/"
OUTPUT_BUCKET = "vulnguard-athena-992382575404"
IMAGE = "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"
INSTANCE_TYPE = "ml.m5.large"
MAX_RUNTIME_SECONDS = 600
TRAIN_SCRIPT = Path(__file__).parent / "train.py"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="actually launch the job")
    args = parser.parse_args()

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    s3 = session.client("s3")
    sm = session.client("sagemaker")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    job_name = f"vulnguard-kev-{stamp}"
    code_key = f"sagemaker-code/{job_name}/sourcedir.tar.gz"
    code_uri = f"s3://{OUTPUT_BUCKET}/{code_key}"
    output_uri = f"s3://{OUTPUT_BUCKET}/sagemaker-output/"

    config = {
        "TrainingJobName": job_name,
        "AlgorithmSpecification": {"TrainingImage": IMAGE, "TrainingInputMode": "File"},
        "RoleArn": ROLE_ARN,
        "InputDataConfig": [{
            "ChannelName": "train",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix", "S3Uri": DATA_URI,
                "S3DataDistributionType": "FullyReplicated"}},
        }],
        "OutputDataConfig": {"S3OutputPath": output_uri},
        "ResourceConfig": {"InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "VolumeSizeInGB": 5},
        "StoppingCondition": {"MaxRuntimeInSeconds": MAX_RUNTIME_SECONDS},
        "HyperParameters": {
            "sagemaker_program": "train.py",
            "sagemaker_submit_directory": code_uri,
            "sagemaker_region": REGION,
        },
    }

    print("Job name :", job_name)
    print("Data     :", DATA_URI)
    print("Code     :", code_uri)
    print("Output   :", output_uri)
    print("Instance :", INSTANCE_TYPE, f"(max {MAX_RUNTIME_SECONDS}s)")

    if not args.run:
        print("[DRY-RUN] Nothing launched. Add --run to start the job.")
        return

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(TRAIN_SCRIPT, arcname="train.py")
    s3.put_object(Bucket=OUTPUT_BUCKET, Key=code_key, Body=buf.getvalue())
    sm.create_training_job(**config)
    print("[LAUNCHED]", job_name)


if __name__ == "__main__":
    main()
