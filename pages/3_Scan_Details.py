
import importlib
import json
import streamlit as st
from src.agents import llm_explanation as llm_explanation_module
from src.agents.security_workflow_graph import run_security_workflow
from src.database.queries import (
    get_scan_history,
    get_scan_details
)
from src.database.db import get_scan_test_plan, save_scan_test_plan
from src.utils import ui

importlib.reload(ui)
importlib.reload(llm_explanation_module)
LLMExplanationAgent = llm_explanation_module.LLMExplanationAgent


st.set_page_config(
    page_title="Scan Details | VulnGuard AI",
    page_icon="🛡️",
    layout="wide"
)

ui.apply_app_styles()
ui.render_page_header(
    "Scan details",
    "Review the request, its dependencies, and the status history recorded for this scan.",
)

st.divider()


# --------------------------------------------------
# 1. LOAD AVAILABLE SCANS
# --------------------------------------------------

scans = get_scan_history(limit=500)

if not scans:

    st.info(
        "No scans are available yet. "
        "Submit a new scan from the New Scan page."
    )

    st.stop()


# --------------------------------------------------
# 2. SELECT A SCAN
# --------------------------------------------------

scan_ids = [
    scan["scan_id"]
    for scan in scans
]


# Prepare readable labels for the selectbox
scan_labels = {
    scan["scan_id"]: (
        f"{scan['project_name']} | "
        f"{scan['scan_id'][:8]} | "
        f"{scan['status']}"
    )
    for scan in scans
}


selected_scan_id = st.selectbox(
    "Select a scan",
    options=scan_ids,
    format_func=lambda scan_id: scan_labels[scan_id]
)


# --------------------------------------------------
# 3. GET SCAN DETAILS
# --------------------------------------------------

details = get_scan_details(selected_scan_id)

if details is None:

    st.error("The selected scan could not be found.")

    st.stop()


scan = details["scan"]
dependencies = details["dependencies"]
history = details["status_history"]
event = details["event"]
analysis_result = details.get("analysis_result")


# --------------------------------------------------
# 4. SUMMARY AND DETAIL SECTIONS
# --------------------------------------------------

status = scan["status"]
status_col, dependency_col, history_col = st.columns(3)
status_col.metric("Current status", status.replace("_", " ").title())
dependency_col.metric("Dependencies", len(dependencies))
history_col.metric("Status changes", len(history))

overview_tab, dependencies_tab, analysis_tab, workflow_tab, event_tab = st.tabs(
    ["Overview", "Dependencies", "Analysis", "Workflow", "Original event"]
)

with overview_tab:
    st.subheader(scan["project_name"])
    st.caption("Scan identifier")
    st.code(scan["scan_id"], language=None)

    info_col, time_col = st.columns(2, gap="large")
    with info_col:
        st.markdown("**Current status**")
        if status == "COMPLETED":
            st.success(status.replace("_", " ").title())
        elif status == "FAILED":
            st.error(status.replace("_", " ").title())
        elif status == "REJECTED":
            st.warning(status.replace("_", " ").title())
        else:
            st.info(status.replace("_", " ").title())
    with time_col:
        st.markdown("**Submitted**")
        st.write(scan["submitted_at"])
        st.markdown("**Received**")
        st.write(scan["received_at"])
        st.markdown("**Last updated**")
        st.write(scan["updated_at"])

with dependencies_tab:
    st.subheader("Packages included in this request")
    if dependencies:
        dependency_table = [
            {
                "Package": dependency["name"],
                "Version": dependency["version"],
                "Ecosystem": dependency["ecosystem"],
            }
            for dependency in dependencies
        ]
        st.dataframe(
            dependency_table,
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No dependencies recorded for this scan.")

with analysis_tab:
    st.subheader("Vulnerability analysis")

    if analysis_result is None:
        st.info(
            "Analysis results are not available yet. "
            "The scan may still be waiting for analysis."
        )
    elif "error" in analysis_result:
        st.error(analysis_result["error"])
    else:
        findings = analysis_result.get("vulnerabilities", [])
        unresolved = analysis_result.get("unresolved", [])
        stored_explanations = {
            item.get("cve_id"): item
            for item in analysis_result.get("llm_explanations", [])
            if isinstance(item, dict)
        }
        stored_plans = {
            item.get("cve_id"): item
            for item in analysis_result.get("security_test_plans", [])
            if isinstance(item, dict)
        }
        stored_reports = {
            item.get("cve_id"): item
            for item in analysis_result.get("final_reports", [])
            if isinstance(item, dict)
        }
        st.caption(f"Analyzed at: {analysis_result.get('analyzed_at', 'Unknown')}")

        result_col, unresolved_col = st.columns(2)
        result_col.metric("Affected CVEs", len(findings))
        unresolved_col.metric("Unresolved entries", len(unresolved))

        if findings:
            for index, finding in enumerate(findings, start=1):
                risk = finding.get("risk", {})
                cve_id = finding.get("cve_id", "Unknown CVE")
                title = (
                    f"{index}. {cve_id} · "
                    f"{risk.get('level', 'UNKNOWN')} · "
                    f"{risk.get('score', 'N/A')}/100"
                )

                with st.expander(title):
                    st.write(finding.get("description") or "No description available.")
                    st.markdown("**Risk assessment**")
                    st.json(risk)
                    explanation_key = (
                        f"ai_explanation_{selected_scan_id}_{cve_id}"
                    )

                    if st.button(
                        "Explain with AI",
                        key=f"explain_{selected_scan_id}_{cve_id}",
                    ):
                        try:
                            with st.spinner("Generating explanation..."):
                                result = LLMExplanationAgent().explain(finding)

                            st.session_state[explanation_key] = result
                        except Exception as error:
                            st.error(f"Could not generate the explanation: {error}")

                    explanation_result = st.session_state.get(
                        explanation_key,
                        stored_explanations.get(cve_id, {}),
                    ) or {}
                    if explanation_result:
                        verified_facts = explanation_result.get("verified_facts") or {
                            "cve_id": cve_id,
                            "risk": risk,
                            "affected_packages": finding.get("affected_packages", []),
                            "recommendations": finding.get("recommendations", []),
                        }
                        current_warnings = LLMExplanationAgent._validate_generated_explanation(
                            explanation_result.get("explanation", ""),
                            verified_facts,
                        )
                        current_errors = LLMExplanationAgent._blocking_validation_errors(
                            current_warnings
                        )
                        explanation_result["validation_warnings"] = current_warnings
                        explanation_result["validation_errors"] = current_errors
                        explanation_result["validation_version"] = 2
                        st.markdown("**AI explanation**")
                        warnings = explanation_result.get("validation_warnings", [])
                        errors = explanation_result.get("validation_errors", [])
                        if errors:
                            st.warning(
                                "The explanation failed fact validation and is withheld. "
                                "Use the deterministic findings below as the source of truth."
                            )
                            for error in errors:
                                st.write(f"- {error}")
                            with st.expander("View untrusted AI output"):
                                st.write(explanation_result.get("explanation", "⚠️ Explanation unavailable."))
                        else:
                            st.write(explanation_result.get("explanation", "⚠️ Explanation unavailable."))
                            st.caption(
                                "AI-generated text can still be inaccurate. "
                                "The deterministic findings remain the source of truth."
                            )
                            if warnings:
                                with st.expander("Validation notes (source facts remain authoritative)"):
                                    for warning in warnings:
                                        st.write(f"- {warning}")

                    packages = finding.get("affected_packages", [])
                    if packages:
                        st.markdown("**Affected package versions**")
                        st.dataframe(
                            [
                                {
                                    "Package": package.get("package_name"),
                                    "Ecosystem": package.get("ecosystem"),
                                    "Installed version": package.get("installed_version"),
                                    "Version status": package.get("version_status"),
                                    "Fixed versions": ", ".join(package.get("fixed_versions", [])),
                                }
                                for package in packages
                            ],
                            width="stretch",
                            hide_index=True,
                        )

                    for explanation in finding.get("analysis", []):
                        st.write(f"• {explanation}")

                    recommendations = finding.get("recommendations", [])
                    if recommendations:
                        st.markdown("**Recommendations**")
                        for recommendation in recommendations:
                            st.write(f"- {recommendation}")

                    st.markdown("**Optional security test plan**")
                    st.caption(
                        "Agent 1 proposes a plan from verified analysis data. "
                        "After approval, Agent 2 installs only the pinned PyPI wheel in a "
                        "resource-limited Docker container and inspects package metadata. "
                        "It does not import the package or run project code."
                    )

                    plan_key = f"test_plan_{selected_scan_id}_{cve_id}"
                    test_plan = st.session_state.get(plan_key)
                    if test_plan is None:
                        test_plan = get_scan_test_plan(selected_scan_id, cve_id)
                    if test_plan is None:
                        test_plan = stored_plans.get(cve_id)
                        if test_plan is not None:
                            test_plan = dict(test_plan)
                            if cve_id in stored_reports:
                                test_plan["final_report"] = stored_reports[cve_id]
                            save_scan_test_plan(selected_scan_id, cve_id, test_plan)
                    if test_plan is not None:
                        st.session_state[plan_key] = test_plan

                    if test_plan and test_plan.get("execution_status") == "RUNNING":
                        test_plan["execution_status"] = "FAILED"
                        test_plan["execution_error"] = (
                            "The application stopped while this check was running. "
                            "Review the plan before generating a new one."
                        )
                        for test in test_plan.get("tests", []):
                            if test.get("execution_status") in {"NOT_STARTED", "RUNNING"}:
                                test["execution_status"] = "FAILED"
                                test["execution_result"] = {
                                    "execution_status": "FAILED",
                                    "message": test_plan["execution_error"],
                                }
                        save_scan_test_plan(selected_scan_id, cve_id, test_plan)
                        st.session_state[plan_key] = test_plan

                    if test_plan is None and st.button(
                        "Generate report and test plan",
                        key=f"generate_plan_{selected_scan_id}_{cve_id}",
                    ):
                        try:
                            with st.spinner("Agent 1 is preparing the report and plan..."):
                                workflow_result = run_security_workflow(
                                    {
                                        "scan_id": selected_scan_id,
                                        "finding": finding,
                                    }
                                )
                            st.session_state[plan_key] = workflow_result["test_plan"]
                            st.session_state[explanation_key] = workflow_result["explanation"]
                            st.session_state[plan_key]["final_report"] = workflow_result[
                                "final_report"
                            ]
                            save_scan_test_plan(
                                selected_scan_id,
                                cve_id,
                                st.session_state[plan_key],
                            )
                            st.rerun()
                        except Exception as error:
                            st.error(f"Could not prepare the report and plan: {error}")

                    test_plan = st.session_state.get(plan_key)
                    if test_plan:
                        st.write(f"Approval status: {test_plan['approval_status']}")
                        st.write(f"Execution status: {test_plan['execution_status']}")
                        if test_plan["approval_status"] == "REJECTED":
                            st.warning("The plan was rejected and cannot be executed.")
                        elif test_plan["approval_status"] == "APPROVED":
                            st.warning(
                                "The Docker sandbox verifies the package wheel and its installed "
                                "version only. It does not execute the scanned application or its tests."
                            )
                            final_report = test_plan.get("final_report", {})
                            if final_report.get("workflow_status") == "FAILED":
                                st.error("The verification stage failed. Review the final report.")
                            elif test_plan["execution_status"] == "NOT_STARTED":
                                st.success(
                                    f"Approved by {test_plan['approval']['reviewer']}. "
                                    "Execution has not started."
                                )
                            elif test_plan["execution_status"] == "RUNNING":
                                st.info("The approved check is running.")
                            elif test_plan["execution_status"] == "COMPLETED":
                                st.success("The approved check completed.")
                            elif test_plan["execution_status"] == "FAILED":
                                st.error(
                                    "The approved check failed: "
                                    + test_plan.get("execution_error", "See execution results below.")
                                )

                        if not test_plan.get("tests"):
                            st.info("No package-version checks could be generated for this finding.")
                        else:
                            for test in test_plan["tests"]:
                                with st.expander(
                                    f"{test['title']} — {test['target']['package_name']}"
                                ):
                                    st.write(test["objective"])
                                    st.write(
                                        "Target: "
                                        f"{test['target'].get('package_name')} "
                                        f"({test['target'].get('ecosystem')})"
                                    )
                                    st.write("Steps:")
                                    for step in test["steps"]:
                                        st.write(f"- {step}")
                                    st.write(f"Expected result: {test['expected_result']}")

                            if test_plan["approval_status"] == "PENDING_APPROVAL":
                                reviewer = st.text_input(
                                    "Reviewer name *",
                                    key=f"reviewer_{selected_scan_id}_{cve_id}",
                                    placeholder="e.g. sec-admin (required to approve or reject)",
                                )
                                rejection_reason = st.text_input(
                                    "Reason for rejection (required only to reject)",
                                    key=f"reject_reason_{selected_scan_id}_{cve_id}",
                                    placeholder="e.g. package not in active runtime path",
                                )
                                approve_col, reject_col = st.columns(2)

                                has_reviewer = bool(reviewer and reviewer.strip())
                                has_rejection_reason = bool(rejection_reason and rejection_reason.strip())

                                if approve_col.button(
                                    "Approve plan",
                                    key=f"approve_plan_{selected_scan_id}_{cve_id}",
                                    disabled=not has_reviewer,
                                    help="Enter a reviewer name above to approve the plan." if not has_reviewer else None,
                                    type="primary",
                                ):
                                    if not has_reviewer:
                                        st.error("Enter a reviewer name before approving.")
                                    else:
                                        try:
                                            with st.spinner(
                                                "Saving the plan approval..."
                                            ):
                                                workflow_result = run_security_workflow(
                                                    {
                                                        "scan_id": selected_scan_id,
                                                        "finding": finding,
                                                        "explanation": explanation_result,
                                                        "test_plan": test_plan,
                                                        "approval_decision": "APPROVE",
                                                        "reviewer": reviewer.strip(),
                                                        "stop_after_approval": True,
                                                    },
                                                )
                                            st.session_state[plan_key] = workflow_result[
                                                "test_plan"
                                            ]
                                            st.session_state[plan_key]["final_report"] = (
                                                workflow_result["final_report"]
                                            )
                                            save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                st.session_state[plan_key],
                                            )
                                            st.rerun()
                                        except Exception as error:
                                            st.error(f"Could not approve the plan: {error}")

                                if reject_col.button(
                                    "Reject plan",
                                    key=f"reject_plan_{selected_scan_id}_{cve_id}",
                                    disabled=not (has_reviewer and has_rejection_reason),
                                    help="Enter both a reviewer name and a rejection reason to reject." if not (has_reviewer and has_rejection_reason) else None,
                                ):
                                    if not has_reviewer or not has_rejection_reason:
                                        st.error(
                                            "Enter both a reviewer name and a rejection reason."
                                        )
                                    else:
                                        try:
                                            workflow_result = run_security_workflow(
                                                {
                                                    "scan_id": selected_scan_id,
                                                    "finding": finding,
                                                    "explanation": explanation_result,
                                                    "test_plan": test_plan,
                                                    "approval_decision": "REJECT",
                                                    "reviewer": reviewer,
                                                    "rejection_reason": rejection_reason,
                                                }
                                            )
                                            st.session_state[plan_key] = workflow_result[
                                                "test_plan"
                                            ]
                                            st.session_state[plan_key]["final_report"] = (
                                                workflow_result["final_report"]
                                            )
                                            save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                st.session_state[plan_key],
                                            )
                                            st.rerun()
                                        except Exception as error:
                                            st.error(f"Could not reject the plan: {error}")

                            elif (
                                test_plan["approval_status"] == "APPROVED"
                                and test_plan["execution_status"] in {"NOT_STARTED", "FAILED"}
                                and st.button(
                                    "Retry approved package-version check"
                                    if test_plan["execution_status"] == "FAILED"
                                    else "Run approved package-version check",
                                    key=f"execute_plan_{selected_scan_id}_{cve_id}",
                                    type="primary",
                                )
                            ):
                                try:
                                    with st.spinner("Agent 2 is running the approved check..."):
                                        workflow_result = run_security_workflow(
                                            {
                                                "scan_id": selected_scan_id,
                                                "finding": finding,
                                                "explanation": explanation_result,
                                                "test_plan": test_plan,
                                            },
                                            on_status_change=lambda updated_plan: save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                updated_plan,
                                            ),
                                        )
                                    st.session_state[plan_key] = workflow_result[
                                        "test_plan"
                                    ]
                                    st.session_state[plan_key]["final_report"] = (
                                        workflow_result["final_report"]
                                    )
                                    save_scan_test_plan(
                                        selected_scan_id,
                                        cve_id,
                                        st.session_state[plan_key],
                                    )
                                    st.rerun()
                                except Exception as error:
                                    st.error(f"Could not execute the approved check: {error}")

                            if test_plan.get("execution_results"):
                                st.markdown("**Execution results**")
                                st.dataframe(
                                    test_plan["execution_results"],
                                    width="stretch",
                                    hide_index=True,
                                )

                            if test_plan.get("final_report"):
                                with st.expander("Final workflow report"):
                                    st.json(test_plan["final_report"])
                                    report_json_str = json.dumps(
                                        test_plan["final_report"],
                                        indent=2,
                                        ensure_ascii=False,
                                    )
                                    st.download_button(
                                        label="📥 Download final report (JSON)",
                                        data=report_json_str,
                                        file_name=f"vulnguard_report_{selected_scan_id[:8]}_{cve_id}.json",
                                        mime="application/json",
                                        key=f"download_report_{selected_scan_id}_{cve_id}",
                                        width="stretch",
                                    )
        else:
            st.success("No affected vulnerabilities were confirmed for this scan.")

        if unresolved:
            with st.expander("Review unresolved entries"):
                st.dataframe(unresolved, width="stretch", hide_index=True)

with workflow_tab:
    st.subheader("Status timeline")
    if history:
        for index, record in enumerate(history):
            st.markdown(f"**{index + 1:02d} · {record['status'].replace('_', ' ').title()}**")
            st.caption(record["changed_at"])
            if record["details"]:
                st.write(record["details"])
            if index < len(history) - 1:
                st.divider()
    else:
        st.info("No status history available.")

with event_tab:
    st.caption("The original request message received from Kafka.")
    st.json(event)

st.caption("Scan information is retrieved from the local SQLite database.")
