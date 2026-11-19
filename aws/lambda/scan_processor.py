"""Fonction AWS Lambda pour l'ingestion et l'évaluation de scans de vulnérabilités."""

import json
from datetime import datetime, timezone
from decimal import Decimal
import boto3

# Connexion aux services AWS managés
dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table("VulnGuardScans")


def lambda_handler(event, context):
    """
    Point d'entrée de la fonction AWS Lambda.
    Reçoit un scan (JSON), évalue les risques et persiste le résultat dans DynamoDB.
    """
    print("Événement reçu par AWS Lambda :", json.dumps(event))

    # Extraction des données du scan
    scan_id = event.get("scan_id", f"lambda-scan-{int(datetime.now().timestamp())}")
    project_name = event.get("project_name", "Projet Sans Nom")
    dependencies = event.get("dependencies", [])

    # Exemple de règles d'évaluation des dépendances
    cve_detectees = []
    score_total = 0.0

    # Simulation d'analyse rapide sur les packages connus
    known_vulnerable_packages = {
        "urllib3": ("CVE-2024-35195", 33.74, "MEDIUM"),
        "open-webui": ("CVE-2024-47081", 85.0, "HIGH"),
        "requests": ("CVE-2023-32681", 61.2, "MEDIUM"),
    }

    for dep in dependencies:
        pkg_name = dep.get("name", "").lower()
        if pkg_name in known_vulnerable_packages:
            cve, score, level = known_vulnerable_packages[pkg_name]
            cve_detectees.append(cve)
            score_total = max(score_total, score)

    risk_level = "LOW"
    if score_total >= 70:
        risk_level = "HIGH"
    elif score_total >= 30:
        risk_level = "MEDIUM"

    now_iso = datetime.now(timezone.utc).isoformat()

    # Enregistrement direct dans Amazon DynamoDB
    item = {
        "scan_id": scan_id,
        "project_name": project_name,
        "status": "ANALYZED_BY_LAMBDA",
        "created_at": now_iso,
        "updated_at": now_iso,
        "cve_count": len(cve_detectees),
        "cve_ids": cve_detectees,
        "risk_score": Decimal(str(round(score_total, 2))),
        "risk_level": risk_level,
        "engine": "AWS-Lambda-Serverless",
    }

    table.put_item(Item=item)
    print(f"Scan {scan_id} persisté avec succès dans DynamoDB.")

    return {
        "statusCode": 200,
        "body": {
            "message": "Scan analysé et persisté avec succès par AWS Lambda",
            "scan_id": scan_id,
            "cve_detected": cve_detectees,
            "risk_score": float(score_total),
            "risk_level": risk_level,
        },
    }


if __name__ == "__main__":
    # Test local hors cloud
    test_event = {
        "scan_id": "test-local-lambda-001",
        "project_name": "mon-app-test",
        "dependencies": [
            {"name": "requests", "version": "2.31.0"},
            {"name": "urllib3", "version": "2.2.1"},
        ],
    }
    result = lambda_handler(test_event, None)
    print("Résultat du test local de la Lambda :", json.dumps(result, indent=2))