from pathlib import Path
import argparse
import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
BUCKET = "vulnguard-ai-2026"
REGION = "us-east-1"
PROFILE = "learnerlab"

DATASETS = {
    "data/processed/osv_records.csv": "processed/osv/osv_records.csv",
    "data/raw/epss/epss_scores-current.csv.gz": "raw/epss/epss_scores-current.csv.gz",
    "data/raw/kev/known_exploited_vulnerabilities.json": "raw/kev/known_exploited_vulnerabilities.json",
}

def main():
    parser = argparse.ArgumentParser(description="Upload VulnGuard datasets to S3")
    parser.add_argument("--upload", action="store_true",
                        help="Actually upload files (default is dry-run)")
    args = parser.parse_args()

    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    s3 = session.client("s3")

    for local_path, s3_key in DATASETS.items():
        file_path = ROOT / local_path

        if not file_path.is_file():
            print(f"[MISSING] {local_path}")
            continue

        print(f"[FOUND] {local_path} ({file_path.stat().st_size:,} bytes)")

        if args.upload:
            try:
                s3.upload_file(str(file_path), BUCKET, s3_key)
                print(f"[UPLOADED] s3://{BUCKET}/{s3_key}")
            except ClientError as error:
                print(f"[ERROR] {s3_key}: {error}")
        else:
            print(f"[DRY RUN] Would upload to s3://{BUCKET}/{s3_key}")

    if not args.upload:
        print("\nDry run complete. No files were uploaded.")

if __name__ == "__main__":
    main()
