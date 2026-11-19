"""Module d'export et d'archivage des rapports d'audit VulnGuard AI vers Amazon S3."""

import os
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


# Nom du bucket créé à l'étape 0.4
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "vulnguard-ai-2026")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", "learnerlab")


def get_s3_client():
    """Initialise le client S3 avec le profil LearnerLab ou les variables d'environnement."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        return session.client("s3")
    except Exception:
        # Fallback standard si le profil par défaut est utilisé
        return boto3.client("s3", region_name=AWS_REGION)


def upload_report_to_s3(scan_id: str, cve_id: str, report_text: str) -> dict:
    """
    Téléverse un rapport d'audit en français dans le dossier reports/ du bucket S3.
    
    Retourne un dictionnaire avec le statut et l'URL S3 du fichier archivé.
    """
    s3 = get_s3_client()
    
    # Nom du fichier horodaté dans S3
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    s3_key = f"reports/rapport_{scan_id[:8]}_{cve_id}_{timestamp}.txt"
    
    try:
        s3.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=report_text.encode("utf-8"),
            ContentType="text/plain; charset=utf-8",
            ServerSideEncryption="AES256",
        )
        s3_uri = f"s3://{S3_BUCKET_NAME}/{s3_key}"
        print(f"✅ Rapport archivé avec succès sur S3 : {s3_uri}")
        return {
            "success": True,
            "s3_uri": s3_uri,
            "s3_key": s3_key,
        }
    except ClientError as e:
        error_msg = e.response["Error"]["Message"]
        print(f"❌ Erreur lors du téléversement sur S3 : {error_msg}")
        return {
            "success": False,
            "error": error_msg,
        }


if __name__ == "__main__":
    # Test autonome d'upload
    print(f"Test d'envoi d'un rapport de test vers s3://{S3_BUCKET_NAME}/...")
    sample_text = (
        "====================================================\n"
        "TEST D'ARCHIVAGE RAPPORT VULNGUARD AI VERS AMAZON S3\n"
        f"Généré le : {datetime.now().isoformat()}\n"
        "Statut : TEST VALIDÉ\n"
        "===================================================="
    )
    result = upload_report_to_s3(
        scan_id="test-scan-001",
        cve_id="CVE-2024-TEST",
        report_text=sample_text,
    )
    print("Résultat :", result)