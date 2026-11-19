"""Coordinate enrichment, risk scoring, LLM explanations and test planning."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.contracts import validate_analysis_result
from src.services.enrichment_adapter import (
    Dependency,
    EnrichmentAdapter,
    Vulnerability,
)

AnalysisComponent = Callable[[Sequence[Vulnerability]], dict[str, Any]]


@dataclass(frozen=True)
class AnalysisResult:
    """Structured result of one scan analysis attempt."""

    scan_id: str
    vulnerabilities: list[Vulnerability]
    risk_assessment: dict[str, Any] | None = None
    ml_prediction: dict[str, Any] | None = None
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    llm_explanations: list[dict[str, Any]] = field(default_factory=list)
    security_test_plans: list[dict[str, Any]] = field(default_factory=list)
    final_reports: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a mapping for persistence/API use."""
        return validate_analysis_result({
            "scan_id": self.scan_id,
            "schema_version": "1.0",
            "vulnerabilities": self.vulnerabilities,
            "risk_assessment": self.risk_assessment,
            "ml_prediction": self.ml_prediction,
            "unresolved": self.unresolved,
            "llm_explanations": self.llm_explanations,
            "security_test_plans": self.security_test_plans,
            "final_reports": self.final_reports,
        })


class AnalysisService:
    """Coordinate enrichment and optional analysis components."""

    def __init__(
        self,
        enrichment_adapter: EnrichmentAdapter,
        risk_scorer: AnalysisComponent | None = None,
        ml_predictor: AnalysisComponent | None = None,
        llm_explainer: Any | None = None,
        test_generator: Any | None = None,
    ) -> None:
        self._enrichment_adapter = enrichment_adapter
        self._risk_scorer = risk_scorer
        self._ml_predictor = ml_predictor
        self._llm_explainer = llm_explainer
        self._test_generator = test_generator

    def analyze(
        self,
        scan_id: str,
        dependencies: Sequence[Dependency],
    ) -> AnalysisResult:
        """Analyze a scan and return findings without persisting them."""
        normalized_scan_id = self._validate_scan(scan_id, dependencies)
        dependency_snapshot = [dict(item) for item in dependencies]

        enrichment = self._enrichment_adapter.enrich_dependencies(
            dependency_snapshot
        )
        vulnerabilities = enrichment["findings"]
        unresolved = enrichment["unresolved"]

        risk_assessment = self._run_component(
            self._risk_scorer,
            vulnerabilities,
            "risk scorer",
        )
        ml_prediction = self._run_component(
            self._ml_predictor,
            vulnerabilities,
            "ML predictor",
        )

        return AnalysisResult(
            scan_id=normalized_scan_id,
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            ml_prediction=ml_prediction,
            unresolved=unresolved,
        )

    def analyze_with_security_workflow(
        self,
        scan_id: str,
        dependencies: Sequence[Dependency],
    ) -> AnalysisResult:
        """
        Run scan analysis, LLM explanations and security test planning.

        Test plans remain pending human approval. This method never executes
        security tests.
        """
        result = self.analyze(scan_id, dependencies)

        from src.agents.report_and_plan_agent import ReportAndPlanAgent
        from src.agents.security_workflow_graph import run_security_workflow

        report_agent = ReportAndPlanAgent(
            explainer=self._llm_explainer,
            test_generator=self._test_generator,
        )
        llm_explanations: list[dict[str, Any]] = []
        security_test_plans: list[dict[str, Any]] = []
        final_reports: list[dict[str, Any]] = []

        for vulnerability in result.vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise TypeError(
                    "Each vulnerability finding must be a dictionary."
                )

            if not vulnerability.get("cve_id"):
                raise ValueError(
                    "Each vulnerability finding must contain a cve_id."
                )

            llm_input = dict(vulnerability)

            risk = dict(vulnerability.get("risk") or {})

            if isinstance(result.risk_assessment, dict):
                assessments = result.risk_assessment.get("assessments", [])

                matching_risk = next(
                    (
                        item for item in assessments
                        if item.get("cve_id") == vulnerability.get("cve_id")
                    ),
                    None,
                )

                if matching_risk:
                    risk.update({
                        "score": matching_risk.get("risk_score"),
                        "level": matching_risk.get("risk_level"),
                        "is_kev": matching_risk.get("is_kev"),
                        "cvss_score": matching_risk.get("cvss_score_used"),
                        "cvss_severity": matching_risk.get("cvss_severity_used"),
                        "cvss_source": matching_risk.get("cvss_provider"),
                        "cvss_version": matching_risk.get("cvss_version_used"),
                        "cvss_standard": matching_risk.get("cvss_source"),
                        "epss_score": matching_risk.get("epss_score_used"),
                        "epss_percentile": matching_risk.get("epss_percentile"),
                        "scoring_basis": matching_risk.get("scoring_basis"),
                        "risk_explanation": matching_risk.get("risk_explanation"),
                    })

            llm_input["risk"] = risk

            # --- LLM is non-fatal: a timeout or connection error must never
            # fail the whole scan.  We catch all exceptions here, store a
            # graceful fallback explanation, and continue processing the
            # remaining vulnerabilities so the scan reaches ANALYZED status.
            try:
                workflow_state = run_security_workflow(
                    {
                        "scan_id": result.scan_id,
                        "finding": llm_input,
                    },
                    report_agent=report_agent,
                )
                llm_explanations.append(workflow_state["explanation"])
                security_test_plans.append(workflow_state["test_plan"])
                final_reports.append(workflow_state["final_report"])

            except Exception as llm_exc:
                import logging
                logging.getLogger(__name__).warning(
                    "LLM workflow failed for %s (%s): %s — using fallback.",
                    vulnerability.get("cve_id"),
                    result.scan_id,
                    llm_exc,
                )
                # Fallback explanation so the scan is never blocked.
                cve_id = vulnerability.get("cve_id", "UNKNOWN")
                llm_explanations.append({
                    "cve_id": cve_id,
                    "status": "EXPLANATION_UNAVAILABLE",
                    "reason": str(llm_exc),
                    "text": (
                        f"AI explanation for {cve_id} could not be generated "
                        f"({llm_exc}). "
                        "The vulnerability data is still available above."
                    ),
                    "warnings": [],
                    "errors": [str(llm_exc)],
                })
                # Still generate the deterministic test plan.
                from src.agents.security_test_generator import SecurityTestGenerator
                fallback_plan = SecurityTestGenerator().generate(llm_input)
                security_test_plans.append(fallback_plan)
                final_reports.append({
                    "cve_id": cve_id,
                    "summary": "Analysis completed without LLM explanation.",
                    "test_plan_ref": fallback_plan.get("plan_id"),
                })

        return AnalysisResult(
            scan_id=result.scan_id,
            vulnerabilities=result.vulnerabilities,
            risk_assessment=result.risk_assessment,
            ml_prediction=result.ml_prediction,
            unresolved=result.unresolved,
            llm_explanations=llm_explanations,
            security_test_plans=security_test_plans,
            final_reports=final_reports,
        )

    @staticmethod
    def _validate_scan(
        scan_id: str,
        dependencies: Sequence[Dependency],
    ) -> str:
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("scan_id must be a non-empty string.")

        if (
            isinstance(dependencies, (str, bytes))
            or not isinstance(dependencies, Sequence)
            or not dependencies
        ):
            raise ValueError("At least one dependency is required.")

        required_fields = ("ecosystem", "name", "version")

        for index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                raise ValueError(
                    f"Dependency at index {index} must be a dictionary."
                )

            for field_name in required_fields:
                value = dependency.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"Dependency at index {index} has an invalid "
                        f"{field_name}."
                    )

        return scan_id.strip()

    @staticmethod
    def _run_component(
        component: AnalysisComponent | None,
        vulnerabilities: Sequence[Vulnerability],
        component_name: str,
    ) -> dict[str, Any] | None:
        if component is None:
            return None

        result = component(vulnerabilities)
        if not isinstance(result, dict):
            raise TypeError(
                f"The {component_name} must return a dictionary."
            )

        return result
