
import importlib
import streamlit as st

from src.database.queries import (
    get_scan_summary,
    get_scan_history
)
from src.utils import ui

importlib.reload(ui)


st.set_page_config(
    page_title="Scan History | VulnGuard AI",
    page_icon="🛡️",
    layout="wide",
)

ui.apply_app_styles()
ui.render_page_header(
    "Scan history",
    "Search and review dependency scan requests recorded in the local workspace.",
)

st.divider()


# ---------------------------------------------
# 1. REFRESH DATA
# ---------------------------------------------

if st.button("Refresh history", help="Reload the scan summary and records."):
    st.rerun()


# ---------------------------------------------
# 2. KPI METRICS
# ---------------------------------------------

summary = get_scan_summary()

st.subheader("Scan overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Scans",
    summary["total"]
)

col2.metric(
    "Waiting Analysis",
    summary["WAITING_ANALYSIS"]
)

col3.metric(
    "Completed",
    summary["COMPLETED"]
)

col4.metric(
    "Failed",
    summary["FAILED"]
)


# ---------------------------------------------
# 3. STATUS DISTRIBUTION
# ---------------------------------------------

st.subheader("Status distribution")

status_data = {
    status: count
    for status, count in summary.items()
    if status != "total" and count > 0
}

if status_data:

    st.bar_chart(status_data)

else:

    st.info("No scans have been submitted yet.")


st.divider()


# ---------------------------------------------
# 4. FILTERS
# ---------------------------------------------

st.subheader("Find a scan")

all_statuses = [
    "All statuses",
    "RECEIVED",
    "WAITING_ANALYSIS",
    "ANALYZED",
    "WAITING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "TESTING",
    "COMPLETED",
    "FAILED"
]

col1, col2 = st.columns(2)

with col1:

    selected_status = st.selectbox(
        "Filter by status",
        all_statuses,
    )

with col2:

    search_term = st.text_input(
        "Search project or scan ID",
        placeholder="Enter a project name or scan ID",
    )


# ---------------------------------------------
# 5. GET FILTERED HISTORY
# ---------------------------------------------

status_filter = (
    None
    if selected_status == "All statuses"
    else selected_status
)

scans = get_scan_history(
    status_filter=status_filter,
    search_term=search_term.strip() or None
)


# ---------------------------------------------
# 6. DISPLAY SCAN TABLE
# ---------------------------------------------

st.subheader("Scan records")

st.caption(
    f"{len(scans)} scan(s) found. Maximum displayed: 200."
)

if scans:

    display_rows = []

    for scan in scans:

        display_rows.append({
            "Scan ID": scan["scan_id"],
            "Project": scan["project_name"],
            "Dependencies": scan["dependency_count"],
            "Status": scan["status"],
            "Submitted At": scan["submitted_at"],
            "Received At": scan["received_at"]
        })

    st.dataframe(
        display_rows,
        width="stretch",
        hide_index=True
    )

else:

    st.info(
        "No scans match the selected filters."
    )


# ---------------------------------------------
# 7. HISTORIQUE CLOUD — AMAZON DYNAMODB
# ---------------------------------------------

st.divider()
st.subheader("☁️ Historique Cloud — Amazon DynamoDB")
st.caption("Consultez les audits synchronisés et archivés dans la base NoSQL Cloud d'Amazon.")

if st.button("🔄 Charger les scans depuis Amazon DynamoDB", key="btn_refresh_dynamodb"):
    with st.spinner("Interrogation de la table AWS 'VulnGuardScans'..."):
        try:
            import boto3
            session = boto3.Session(profile_name="learnerlab", region_name="us-east-1")
            ddb = session.resource("dynamodb")
            table = ddb.Table("VulnGuardScans")
            response = table.scan(Limit=20)
            items = response.get("Items", [])

            if items:
                cloud_rows = []
                for item in items:
                    cves = item.get("cve_ids", [])
                    cve_text = ", ".join(cves) if isinstance(cves, list) else str(cves)
                    cloud_rows.append({
                        "Scan ID": item.get("scan_id"),
                        "Projet": item.get("project_name", "N/A"),
                        "Statut": item.get("status"),
                        "Score": f"{item.get('risk_score', 'N/A')}/100",
                        "Niveau": item.get("risk_level", "N/A"),
                        "CVEs Détectées": cve_text or "0",
                        "Date Sync": item.get("created_at", "")[:19].replace("T", " "),
                        "Rapport S3": item.get("report_s3_uri", "N/A"),
                    })
                st.dataframe(cloud_rows, width="stretch", hide_index=True)
                st.success(f"✅ {len(cloud_rows)} scan(s) récupéré(s) en direct depuis DynamoDB (Table: VulnGuardScans).")
            else:
                st.info("Aucun scan archivé dans la table DynamoDB pour le moment.")
        except Exception as e:
            st.warning(
                "⚠️ Impossible de joindre AWS DynamoDB en direct. "
                "Vérifiez que votre session Learner Lab est active."
            )