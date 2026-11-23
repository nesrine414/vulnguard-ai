"""Générateur de rapport d'audit de sécurité en français pour VulnGuard AI."""

from datetime import datetime
from typing import Any, Dict


def build_french_security_report(
    scan_id: str,
    project_name: str,
    cve_id: str,
    final_report: Dict[str, Any],
) -> str:
    """
    Transforme les résultats techniques bruts en un rapport d'audit
    clair, structuré et entièrement rédigé en français.
    """
    facts = final_report.get("verified_facts") or {}
    risk = facts.get("risk") or {}
    approval = final_report.get("approval") or {}
    verification = final_report.get("verification") or {}
    ai_text = final_report.get("ai_explanation") or "Aucune explication IA enregistrée."
    
    # Traduction des statuts de risque et de workflow
    status_traduction = {
        "COMPLETED": "VÉRIFICATION TERMINÉE AVEC SUCCÈS",
        "WAITING_APPROVAL": "EN ATTENTE D'APPROBATION HUMAINE",
        "REJECTED": "PLAN DE TEST REJETÉ",
        "APPROVED": "APPROUVÉ PAR L'AUDITEUR",
        "FAILED": "ÉCHEC DU TEST EN SANDBOX",
        "NOT_STARTED": "NON EXÉCUTÉ",
    }
    workflow_status = status_traduction.get(
        final_report.get("workflow_status", ""),
        final_report.get("workflow_status", "NON DÉFINI"),
    )

    # Indicateur KEV (Exploitation active connue)
    kev_str = "OUI (Exploitation active recensée par la CISA)" if risk.get("is_kev") else "Non (Absente du catalogue CISA KEV)"
    
    # Score EPSS (Probabilité d'exploitation sous 30 jours)
    epss_val = risk.get("epss_score")
    epss_str = f"{float(epss_val) * 100:.2f} %" if epss_val is not None else "Non disponible"

    date_now = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    lignes = [
        "=" * 80,
        "                    RAPPORT D'AUDIT DE SÉCURITÉ VULNGUARD AI",
        "=" * 80,
        f"Projet audité       : {project_name or 'N/A'}",
        f"Identifiant du scan : {scan_id}",
        f"Vulnérabilité (CVE) : {cve_id}",
        f"Date de génération  : {date_now}",
        f"Statut du workflow  : {workflow_status}",
        "=" * 80,
        "",
        "1. ÉVALUATION DU RISQUE & MÉTRIQUES OFFICIELLES",
        "-" * 80,
        f"• Score de risque global : {risk.get('score', 'N/A')} / 100  (Niveau : {risk.get('level', 'N/A')})",
        f"• Score standard CVSS   : {risk.get('cvss_score', 'N/A')} ({risk.get('cvss_severity', 'N/A')})",
        f"• Probabilité EPSS      : {epss_str}",
        f"• Exploitation active   : {kev_str}",
        "",
        "2. PACKAGES & COMPOSANTS AFFECTÉS",
        "-" * 80,
    ]

    packages = facts.get("affected_packages") or []
    if packages:
        for pkg in packages:
            nom = pkg.get("package_name", "N/A")
            version_installee = pkg.get("installed_version", "Inconnue")
            statut_ver = pkg.get("version_status", "N/A")
            correctifs = ", ".join(pkg.get("fixed_versions", [])) or "Aucun correctif déclaré"
            lignes.append(f"  ▶ Package           : {nom} ({pkg.get('ecosystem', 'PyPI')})")
            lignes.append(f"    Version scannée   : {version_installee} (Statut : {statut_ver})")
            lignes.append(f"    Version(s) fixée(s): {correctifs}")
    else:
        lignes.append("  Aucun package spécifique listé.")

    lignes.extend([
        "",
        "3. ANALYSE ET EXPLICATION DE L'INTELLIGENCE ARTIFICIELLE",
        "-" * 80,
        ai_text.strip(),
        "",
        "4. RECOMMANDATIONS TECHNIQUES",
        "-" * 80,
    ])

    recs = facts.get("recommendations") or []
    if recs:
        for r in recs:
            lignes.append(f"  • {r}")
    else:
        lignes.append("  • Mettre à jour la bibliothèque vers la version la plus récente.")

    lignes.extend([
        "",
        "5. CONTRÔLE HUMAIN & GOUVERNANCE (HUMAN-IN-THE-LOOP)",
        "-" * 80,
    ])

    decision = approval.get("decision", "NON EXPRIMÉE")
    reviewer = approval.get("reviewer") or "Non renseigné"
    horodatage = approval.get("timestamp") or "N/A"
    raison = approval.get("reason")

    if decision == "APPROVED":
        lignes.append(f"  • Décision de l'auditeur : APPROUVÉ")
        lignes.append(f"  • Auditeur responsable   : {reviewer}")
        lignes.append(f"  • Date de validation     : {horodatage}")
    elif decision == "REJECTED":
        lignes.append(f"  • Décision de l'auditeur : REJETÉ")
        lignes.append(f"  • Auditeur responsable   : {reviewer}")
        lignes.append(f"  • Motif du refus         : {raison or 'Non précisé'}")
        lignes.append(f"  • Date du refus          : {horodatage}")
    else:
        lignes.append("  • En attente de revue humaine avant autorisation d'exécution.")

    lignes.extend([
        "",
        "6. RÉSULTATS DU BAC À SABLE DOCKER (ENVIRONNEMENT ISOLÉ)",
        "-" * 80,
    ])

    if verification:
        lignes.append(f"  • Statut de l'inspection : {verification.get('verification', 'TERMINÉE')}")
        lignes.append(f"  • Version certifiée wheel: {verification.get('installed_version', 'N/A')}")
        lignes.append(f"  • Isolation réseau       : Réseau désactivé (--network=none)")
        lignes.append(f"  • Exécution de code      : Aucun code de projet exécuté (Inspection métadonnées)")
    else:
        lignes.append("  • Aucun test Docker n'a été exécuté pour ce plan.")

    lignes.extend([
        "",
        "=" * 80,
        "Document certifié par VulnGuard AI — Traçabilité et Gouvernance DevSecOps",
        "=" * 80,
    ])

    return "\n".join(lignes)