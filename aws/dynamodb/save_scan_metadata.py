
"""Synchronisation des métadonnées VulnGuard AI vers Amazon DynamoDB."""

import os
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import boto3
from botocore.exceptions import BotoCoreError, ClientError


TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "VulnGuardScans")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", "learnerlab")


def get_dynamodb_resource():
    """Initialise la ressource DynamoDB."""
    session = boto3.Session(
        profile_name=AWS_PROFILE,
        region_name=AWS_REGION,
    )
    return session.resource("dynamodb")


def save_scan_to_dynamodb(
    scan_id: str,
    project_name: str,
    status: str,
    risk_score: float | int | None = None,
    risk_level: str | None = None,
    cve_list: list[str] | None = None,
    report_s3_uri: str | None = None,
) -> dict:
    """Enregistre les métadonnées d'un scan dans DynamoDB."""

    if not scan_id:
        return {"success": False, "error": "scan_id est obligatoire."}

    try:
        table = get_dynamodb_resource().Table(TABLE_NAME)

        now_iso = datetime.now(timezone.utc).isoformat()
        cves = cve_list or []

        item = {
            "scan_id": scan_id,
            "project_name": project_name or "N/A",
            "status": status,
            "created_at": now_iso,
            "updated_at": now_iso,
            "cve_count": len(cves),
            "cve_ids": cves,
        }

        if risk_score is not None:
            try:
                item["risk_score"] = Decimal(str(risk_score)).quantize(
                    Decimal("0.01")
                )
            except (InvalidOperation, ValueError, TypeError):
                return {
                    "success": False,
                    "error": "risk_score doit être un nombre valide.",
                }

        if risk_level:
            item["risk_level"] = risk_level

        if report_s3_uri:
            item["report_s3_uri"] = report_s3_uri

        table.put_item(Item=item)

        print(f"Scan {scan_id} enregistré dans DynamoDB.")

        return {"success": True, "item": item}

    except (ClientError, BotoCoreError, OSError) as error:
        error_msg = str(error)
        print(f"Erreur DynamoDB : {error_msg}")
        return {"success": False, "error": error_msg}


def get_scan_from_dynamodb(scan_id: str) -> dict | None:
    """Récupère un scan à partir de son identifiant."""

    try:
        table = get_dynamodb_resource().Table(TABLE_NAME)
        response = table.get_item(Key={"scan_id": scan_id})
        return response.get("Item")

    except (ClientError, BotoCoreError, OSError) as error:
        print(f"Erreur de lecture DynamoDB : {error}")
        return None


if __name__ == "__main__":
    print(f"Test DynamoDB : table {TABLE_NAME}")

    test_scan_id = "demo-scan-aws-001"

    result = save_scan_to_dynamodb(
        scan_id=test_scan_id,
        project_name="demo-python-app",
        status="ANALYZED",
        risk_score=72.5,
        risk_level="HIGH",
        cve_list=[
            "CVE-2024-35195",
            "CVE-2024-47081",
        ],
        report_s3_uri=(
            "s3://vulnguard-ai-2026/reports/"
            "rapport_test-sca_CVE-2024-TEST_20261119_145509.txt"
        ),
    )

    print("Résultat écriture :", result)

    if result.get("success"):
        print("\nLecture de vérification :")
        retrieved_item = get_scan_from_dynamodb(test_scan_id)
        print("Scan récupéré :", retrieved_item)
