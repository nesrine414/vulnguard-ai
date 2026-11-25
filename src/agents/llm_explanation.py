
import copy
import json
import re
from decimal import Decimal, InvalidOperation

from src.agents.llm.ollama_provider import OllamaProvider


class LLMExplanationAgent:
    """
    Generates a human-readable vulnerability explanation using an LLM.

    The LLM explains the analysis, while verified source data
    remains independently available in verified_facts.
    """

    HARD_VALIDATION_PREFIXES = (
        "KEV contradiction:",
        "EPSS percentile contradiction:",
        "Risk metric mismatch:",
        "Risk metric contradiction:",
        "Package status contradiction:",
        "CVSS provenance contradiction:",
        "Exploitability condition missing:",
        "Fixed version contradiction:",
    )

    def __init__(self, provider=None):
        self.provider = provider or OllamaProvider()

    @staticmethod
    def _validate_analysis(analysis: dict) -> None:
        """Validate the structure received from VulnerabilityAnalyzer."""

        if not isinstance(analysis, dict):
            raise ValueError("analysis must be a dictionary")

        if not analysis.get("cve_id"):
            raise ValueError("CVE ID is required")

        required_fields = [
            "risk",
            "description",
            "affected_packages",
            "recommendations",
        ]

        missing_fields = [
            field for field in required_fields
            if field not in analysis
        ]

        if missing_fields:
            raise ValueError(
                f"Missing required analysis fields: {missing_fields}"
            )

        if not isinstance(analysis["risk"], dict):
            raise TypeError("analysis['risk'] must be a dictionary")

        if not isinstance(analysis["affected_packages"], list):
            raise TypeError(
                "analysis['affected_packages'] must be a list"
            )

        if not isinstance(analysis["recommendations"], list):
            raise TypeError(
                "analysis['recommendations'] must be a list"
            )

    @staticmethod
    def _build_package_context(package: dict) -> dict:
        """
        Provide package identity and installation status to the LLM.

        Full OSV ranges remain available in verified_facts.
        They are excluded from the prompt to avoid misinterpretation
        of aggregated vulnerability ranges.
        """

        return {
            "package_name": package.get("package_name"),
            "ecosystem": package.get("ecosystem"),
            "purl": package.get("purl"),
            "osv_ids": package.get("osv_ids", []),
            "installed_version": package.get("installed_version"),
            "version_status": package.get("version_status"),
        }

    def _build_prompt(self, analysis: dict) -> str:
        """Build a strict prompt using the analyzer's verified data."""

        packages = [
            self._build_package_context(package)
            for package in analysis["affected_packages"]
        ]

        risk = analysis.get("risk") or {}
        if not isinstance(risk, dict):
            risk = {}

        legacy_cvss_source = risk.get("cvss_source")
        cvss_source = risk.get("cvss_provider") or risk.get("cvss_origin")
        cvss_standard = risk.get("cvss_standard") or risk.get("cvss_type")
        if not cvss_source and isinstance(legacy_cvss_source, str):
            if re.fullmatch(r"CVSS_V[34]", legacy_cvss_source, re.IGNORECASE):
                if not cvss_standard:
                    cvss_standard = legacy_cvss_source
            else:
                cvss_source = legacy_cvss_source

        advisories = [
            {
                "osv_id": advisory.get("osv_id"),
                "summary": advisory.get("summary"),
                "details": advisory.get("details"),
                "published": advisory.get("published"),
                "modified": advisory.get("modified"),
            }
            for advisory in analysis.get("advisories", [])
        ]

        prompt_data = {
            "cve_id": analysis["cve_id"],
            "description": analysis.get("description"),
            "risk": {
                "score": risk.get("score"),
                "level": risk.get("level"),
                "is_kev": risk.get("is_kev"),
                "cvss_score": risk.get("cvss_score"),
                "cvss_severity": risk.get("cvss_severity"),
                "cvss_version": risk.get("cvss_version", risk.get("cvss_version_used")),
                "cvss_source": cvss_source,
                "cvss_standard": cvss_standard,
                "epss_score": risk.get("epss_score"),
                "epss_percentile": risk.get("epss_percentile"),
                "scoring_basis": risk.get("scoring_basis"),
            },
            "advisories": advisories,
            "affected_packages": packages,
            "installed_package_check_performed": analysis.get(
                "installed_package_check_performed",
                False,
            ),
            "recommendations": analysis.get("recommendations", []),
        }

        serialized_data = json.dumps(
            prompt_data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        return f"""
You are a cybersecurity vulnerability analyst.

Your task is to explain the vulnerability using ONLY the supplied
analysis data.

STRICT DATA INTEGRITY RULES:

1. Never invent or modify CVE identifiers, package names, versions,
   CVSS scores, versions or sources, EPSS scores, percentiles, risk scores,
   or dates. Keep every CVSS score attached to its supplied version and
   source; never combine scores from different sources.

2. Treat all supplied values as authoritative.
   If a value is null or missing, say that it is unavailable.
   Never replace missing values with estimates.
   Specifically: In "risk", "score" is the VulnGuard risk score. If "epss_score" is null
   or missing, state that the EPSS score is unavailable. Never assign the value of "score" to "epss_score".

3. Do not calculate or reconstruct vulnerability version ranges.
   The complete OSV ranges are deliberately not included in this prompt.
   Never invent introduced versions, fixed versions, or affected intervals.

4. Keep affected packages separate.
   Never combine information from different packages.

5. Do not claim that an installed package is vulnerable unless its
   version_status is explicitly "AFFECTED".
   AFFECTED means the installed version matches a published affected range.
   It does not by itself establish that the application calls vulnerable
   code or is exploitable in its deployment. If the advisory limits exposure
   to a function, API, feature, or usage pattern, state that condition and
   do not generalize it to every application using the package.

6. Interpret version_status as follows:
   - AFFECTED: the installed version is within a known affected range.
   - NOT_AFFECTED: the installed version is outside known affected ranges.
   - UNKNOWN: the available data cannot establish the status.
   - NOT_CHECKED: no installed-version check was performed.

7. Interpret the is_kev field as an authoritative boolean value.
   You MUST follow these exact rules:
   - If is_kev is true:
     State: "The CVE is listed in the supplied KEV catalog snapshot."
   - If is_kev is false:
     State: "The CVE is not listed in the supplied KEV catalog snapshot."
   - If is_kev is null or missing:
     State: "KEV status is unavailable in the supplied data."
   IMPORTANT:
   - Never describe false as unavailable, unknown, or missing.
   - Never describe false as listed, included, present, or affected in KEV.
   - Never describe true as absent or not listed.
   - Do not contradict the KEV status elsewhere in the explanation.
   - Do not infer exploitation status from a missing KEV entry.
   - Use only the supplied is_kev value. Do not guess.

8. A risk level of UNKNOWN or a scoring basis of NO_DATA does not mean
   that the CVE is rejected, invalid, or harmless.
   Only describe a CVE as rejected if the supplied description or
   advisory explicitly says so.

9. Do not claim that a package has a fixed version unless that
   information is explicitly present in the supplied data.

10. Do not add external facts, references, exploit details, or
    remediation steps that are not supported by the supplied data.

11. If the source data contains contradictory or incomplete information,
    clearly state that limitation instead of resolving it yourself.

12. Do not omit any affected package from the explanation.

STRICT VERSION RULES:
- Never invent, normalize, reformat, or infer version numbers.
- Preserve version strings exactly as supplied.
- An introduced version of "0" must remain "0".
- Do not transform "0" into "0.0.0-0" or another format.
- Explain "introduced: 0" only as the supplied OSV range boundary; do not
  describe it as a literal released package version or release date.
- Distinguish affected ranges from installed versions.
- A fixed version is not an installed version.
- If installed_version is null, say no installed version was provided.
- NOT_CHECKED means the installed version was not checked.
- Never claim the project is vulnerable without an AFFECTED
  installed version status.

STRICT SECURITY RULES:
- Report the exact CVE identifier.
- Report supplied OSV identifiers.
- Report the exact package name and ecosystem.
- Report the exact CVSS score and severity.
- Report the supplied CVSS version and source with its score. If cvss_source is provided in the data, explicitly state "The CVSS score is from <cvss_source>". If either is
  unavailable, say so; do not substitute a value from another advisory.
- Report the exact EPSS score and percentile.
- Explain KEV status using is_kev:
  true means listed in the supplied CISA KEV snapshot.
  false means not listed in that snapshot.
- Report the exact VulnGuard risk score (from "score") and risk level (from "level").
- The VulnGuard score is a prioritization score, not a probability.
- If epss_score is null or missing, state that EPSS is unavailable; never substitute the VulnGuard risk score for it.
- EPSS is an estimated exploitation probability, not severity.
- CRITICAL METRIC FORMATTING:
  * Output the EXACT literal numbers provided in the source data for score, cvss_score, epss_score, and epss_percentile.
  * DO NOT convert EPSS values to percentages (e.g. output 0.0014, NEVER 0.14%; output 0.49, NEVER 49%).
  * DO NOT round, estimate, or change any number.
  * DO NOT add denominators such as "/10" or "/100".
- Describe impact only when the supplied description or advisory explicitly
  supports it. A vulnerability title or class alone is not enough to infer
  data theft, code execution, privilege escalation, or other consequences.
- Do not add generic claims about what an attacker "may" do. If impact is
  not explicitly established by the supplied text, say it is unavailable.
- Keep Potential Impact and Analysis Limitations consistent: do not claim a
  specific impact in one section and say it is unavailable in another.
- If the supplied description/advisory contains only a title or a short
  summary, keep Potential Impact limited to what that text explicitly states.

Do not explain the JSON structure. Explain the vulnerability itself.

SOURCE DATA:

{serialized_data}

Write the explanation using exactly these six sections:

1. Vulnerability Overview
Explain what the vulnerability is, using the supplied description.
If the description is missing, state that it is unavailable.

2. Risk Assessment
Report the supplied risk level, risk score, CVSS information,
EPSS score, EPSS percentile, and KEV status when available.
Do not calculate or alter these values.
Explain when information is unavailable.

3. Affected Packages
List every affected package separately.
For each package, report its ecosystem and installed version status
when available.
Do not reconstruct or invent version ranges.

4. Installed Version Analysis
Explain whether an installed version was checked.
Only describe a package as affected when its status is AFFECTED.
If no installed-version check was performed, say so.

5. Recommendations
Use only the recommendations supplied in the source data.
Do not invent fixed versions or claim that a remediation is available
when the data does not establish this.
When reporting a fixed version for a package, use exactly this phrasing:
"For <package_name>, OSV supplies <version> as a fixed version."
Do not combine the installed version and the fixed version in the same
sentence using transition words such as "upgrade from X to Y" — write
them as separate sentences.

6. Data Limitations
Mention relevant missing or incomplete information.
In particular, distinguish unavailable risk data from evidence
that a vulnerability is rejected or harmless.
Only say KEV status is unavailable when is_kev is null or missing.
When is_kev is false, consistently say it is not listed in the supplied
KEV snapshot; do not call KEV status unavailable in any section.

Be precise, cautious, and technically accurate.
Write the entire explanation in English only; do not mix languages.
Return a readable explanation, not JSON.
"""

    @staticmethod
    def _validate_generated_explanation(explanation: str, verified_facts: dict) -> list:
        """
        Detects a small set of contradictions between the LLM explanation
        and verified source facts. It does not rewrite the explanation.
        """
        warnings = []

        if not isinstance(explanation, str) or not isinstance(verified_facts, dict):
            return warnings

        risk = verified_facts.get("risk", {})
        if not isinstance(risk, dict):
            risk = {}

        text = explanation.lower()

        # Split the explanation into individual sentences.
        sentences = re.split(r"(?<=[.!?])\s+", text)

        kev_positive = False
        kev_negative = False
        kev_unavailable = False

        unavailable_pattern = re.compile(
            r"\b(?:unavailable|not available|missing|unknown|not provided)\b"
        )
        kev_status_unavailable_pattern = re.compile(
            r"\b(?:kev|known exploited vulnerabilities)\b"
            r".{0,30}\bstatus\b.{0,20}"
            r"\b(?:unavailable|not available|missing|unknown|not provided|null)\b"
            r"|"
            r"\bstatus\b.{0,20}"
            r"\b(?:kev|known exploited vulnerabilities)\b"
            r".{0,30}"
            r"\b(?:unavailable|not available|missing|unknown|not provided|null)\b"
        )        

        negative_pattern = re.compile(
            r"\b(?:not\s+(?:listed|included|present|in)|"
            r"does\s+not\s+(?:appear|exist|feature)|"
            r"never\s+(?:listed|included|exploited)|"
            r"absent|excluded|not\s+present)\b"
        )

        positive_pattern = re.compile(
            r"\b(?:listed|included|present|appears)\b"
        )

        for sentence in sentences:
            mentions_kev = (
                "kev" in sentence
                or "known exploited vulnerabilities" in sentence
            )

            if not mentions_kev:
                continue

            if kev_status_unavailable_pattern.search(sentence):
                kev_unavailable = True

            negative_match = negative_pattern.search(sentence)
            positive_match = positive_pattern.search(sentence)

            if negative_match:
                kev_negative = True

            # Do not interpret "not listed" as a positive KEV claim.
            elif positive_match:
                kev_positive = True

        is_kev = risk.get("is_kev")

        if is_kev is True and (kev_negative or kev_unavailable):
            warnings.append(
                "KEV contradiction: the source indicates that the CVE is in KEV, "
                "but the explanation denies this or says the status is unavailable."
            )

        elif is_kev is False and (kev_positive or kev_unavailable):
            warnings.append(
                "KEV contradiction: the source indicates that the CVE is not "
                "in KEV, but the explanation claims it is listed or says the status is unavailable."
            )

        # Check EPSS percentile contradictions sentence by sentence.
        percentile = risk.get("epss_percentile")

        if percentile is not None:
            for sentence in sentences:
                mentions_percentile = (
                    "percentile" in sentence
                )

                says_unavailable = unavailable_pattern.search(sentence)

                if mentions_percentile and says_unavailable:
                    warnings.append(
                        "EPSS percentile contradiction: a percentile value exists "
                        "in the source data, but the explanation says it is unavailable."
                    )
                    break

        # Keep a CVSS value tied to the version and data source selected by
        # the deterministic pipeline. A different source's score is not a
        # substitute for the supplied score.
        cvss_source = (
            risk.get("cvss_provider")
            or risk.get("cvss_origin")
            or risk.get("cvss_source")
        )
        if isinstance(cvss_source, str) and re.fullmatch(
            r"CVSS_V[34]", cvss_source, re.IGNORECASE
        ):
            # Older risk records used cvss_source to mean CVSS type, not origin.
            cvss_source = None
        cvss_version = risk.get("cvss_version", risk.get("cvss_version_used"))
        cvss_sentences = [
            sentence for sentence in sentences
            if re.search(r"\bcvss\b", sentence)
        ]
        if cvss_source:
            expected_source = str(cvss_source).strip().lower()
            source_claim_pattern = re.compile(
                r"\b(?:from|source(?:\s+is)?|provided\s+by|according\s+to)\s+([a-z0-9_.-]+)"
            )
            declared_sources = {
                match.group(1).lower()
                for sentence in cvss_sentences
                for match in source_claim_pattern.finditer(sentence)
                if match.group(1).lower() not in {"not", "null", "none", "unknown", "unavailable", "specified", "provided"}
            }
            wrong_source_claim = any(
                source != expected_source for source in declared_sources
            )
            source_is_present = any(
                expected_source in sentence for sentence in cvss_sentences
            )
            if wrong_source_claim:
                warnings.append(
                    "CVSS provenance contradiction: the explanation attributes the CVSS score "
                    f"to a source other than {cvss_source}."
                )
            elif not source_is_present:
                warnings.append(
                    "CVSS provenance omitted: the supplied CVSS source is not attached to the score."
                )

        if cvss_version is not None:
            expected_version = (
                str(cvss_version).strip().lower().removeprefix("cvss:")
            )
            version_pattern = re.compile(
                r"\bcvss(?::|\s+(?:version\s+)?(?:is\s+)?)\s*v?(\d+\.\d+)\b"
            )
            stated_versions = {
                match.group(1).lower()
                for sentence in cvss_sentences
                for match in version_pattern.finditer(sentence)
            }
            if stated_versions and expected_version not in stated_versions:
                warnings.append(
                    "CVSS provenance contradiction: the explanation gives a CVSS version "
                    f"different from the supplied version {cvss_version}."
                )
            elif not stated_versions:
                warnings.append(
                    "CVSS provenance omitted: the supplied CVSS version is not attached to the score."
                )

        # Enforce advisory-specific exposure limits when they are explicit in
        # the source. In particular, an affected Requests version alone does
        # not show that an application invokes extract_zipped_paths directly.
        advisories = verified_facts.get("advisories", [])
        conditional_functions = []
        if isinstance(advisories, list):
            for advisory in advisories:
                if not isinstance(advisory, dict):
                    continue
                advisory_text = " ".join(
                    str(advisory.get(key) or "")
                    for key in ("summary", "details")
                )
                match = re.search(
                    r"\bextract_zipped_paths\b", advisory_text, re.IGNORECASE
                )
                if match and re.search(
                    r"\bdirect(?:ly)?\b|\bonly\b",
                    advisory_text,
                    re.IGNORECASE,
                ):
                    conditional_functions.append(match.group(0))

        for function_name in conditional_functions:
            mentions_function = re.search(
                rf"\b{re.escape(function_name)}\b", text, re.IGNORECASE
            )
            states_direct_call = re.search(r"\bdirect(?:ly)?\b", text)
            states_normal_use_limit = re.search(
                r"\b(?:standard|normal|default)\b.{0,60}"
                r"\b(?:not affected|unaffected|not vulnerable)\b",
                text,
            )
            if not (
                mentions_function
                and states_direct_call
                and states_normal_use_limit
            ):
                warnings.append(
                    "Exploitability condition missing: the advisory limits exposure to direct "
                    f"use of {function_name}, while the explanation does not preserve that "
                    "condition and the unaffected standard-use case."
                )
                continue

            broad_application_claim = re.search(
                r"\b(?:all|every|any)\s+(?:applications?|apps?)\s+"
                r"(?:using|that\s+use|running)\s+requests\b"
                r".{0,100}\b(?:vulnerable|affected|exploitable)\b",
                text,
            )
            if broad_application_claim:
                warnings.append(
                    "Exploitability condition missing: the explanation says all applications "
                    "using Requests are affected despite the advisory's direct-call requirement."
                )

        # Require key source facts to be represented exactly enough to
        # detect omissions or conflicting values in the generated report.
        cve_id = verified_facts.get("cve_id")
        if cve_id and str(cve_id).lower() not in text:
            warnings.append(
                f"CVE identifier missing: the explanation does not include {cve_id}."
            )

        for advisory in verified_facts.get("advisories", []) or []:
            if not isinstance(advisory, dict):
                continue
            osv_id = advisory.get("osv_id")
            if osv_id and str(osv_id).lower() not in text:
                warnings.append(
                    f"OSV identifier missing: the explanation does not include {osv_id}."
                )

        metric_patterns = {
            "score": re.compile(
                r"\b(?:vulnguard|risk|prioritization|priority)\s+score\b"
            ),
            "cvss_score": re.compile(r"\bcvss(?:\s+v[34])?(?:\s+score)?\b"),
            "epss_score": re.compile(r"\bepss\b(?!\s+percentile)"),
            "epss_percentile": re.compile(r"\bepss\s+percentile\b|\bpercentile\b"),
        }
        metric_unavailable_patterns = {
            "score": re.compile(
                r"\b(?:vulnguard|risk|prioritization|priority)\s+score\b"
            ),
            "level": re.compile(r"\brisk\s+level\b"),
            "cvss_score": re.compile(
                r"\bcvss(?:\s+v[34])?\s+(?:score|rating)\b|"
                r"\bcvss\s+(?:v?\d+\.\d+\s+)?(?:score|rating)\b"
            ),
            "cvss_severity": re.compile(r"\bcvss\s+severity\b"),
            "epss_score": re.compile(r"\bepss\b(?!\s+percentile)"),
            "epss_percentile": re.compile(r"\bepss\s+percentile\b"),
        }

        for field, metric_pattern in metric_unavailable_patterns.items():
            if risk.get(field) is None:
                continue
            for sentence in sentences:
                if metric_pattern.search(sentence) and unavailable_pattern.search(sentence):
                    warnings.append(
                        f"Risk metric contradiction: the explanation says the supplied "
                        f"{field} value is unavailable, but the source provides it."
                    )
                    break

        for field, metric_pattern in metric_patterns.items():
            expected = risk.get(field)
            if expected is None:
                continue

            metric_sentences = [
                sentence for sentence in sentences
                if metric_pattern.search(sentence)
            ]
            if not metric_sentences:
                warnings.append(
                    f"Risk metric omitted: the explanation does not mention "
                    f"the supplied {field} value. The deterministic result remains authoritative."
                )
                continue

            try:
                expected_number = Decimal(str(expected)).normalize()
            except InvalidOperation:
                continue

            stated_numbers = set()
            for sentence in metric_sentences:
                for token in re.findall(r"(?<![\w.])-?\d+(?:\.\d+)?", sentence):
                    try:
                        stated_numbers.add(Decimal(token).normalize())
                    except InvalidOperation:
                        continue

            if expected_number not in stated_numbers:
                warnings.append(
                    f"Risk metric mismatch: the explanation states a value for "
                    f"{field} that does not match the supplied data."
                )

        level = risk.get("level")
        if level and str(level).lower() not in text:
            warnings.append(
                "Risk level missing or mismatched: the explanation does not "
                "state the supplied risk level."
            )

        package_records = verified_facts.get("affected_packages", [])
        if isinstance(package_records, list):
            for package in package_records:
                if not isinstance(package, dict):
                    continue
                package_name = package.get("package_name")
                if package_name and str(package_name).lower() not in text:
                    warnings.append(
                        f"Affected package missing: {package_name} is not mentioned."
                    )
                    continue

                installed_version = package.get("installed_version")
                if installed_version and str(installed_version).lower() not in text:
                    warnings.append(
                        f"Installed version missing: the supplied version for "
                        f"{package_name} ({installed_version}) is not mentioned."
                    )

                ecosystem = package.get("ecosystem")
                if ecosystem and str(ecosystem).lower() not in text:
                    warnings.append(
                        f"Package ecosystem missing: {package_name} is not tied to "
                        f"the supplied ecosystem {ecosystem}."
                    )

                status = str(package.get("version_status") or "").upper()
                package_sentences = [
                    sentence for sentence in sentences
                    if package_name and str(package_name).lower() in sentence
                ]
                package_context = " ".join(package_sentences)
                if status == "AFFECTED" and re.search(
                    r"\b(?:not affected|unaffected|not vulnerable|outside the affected)\b",
                    package_context,
                ):
                    warnings.append(
                        f"Package status contradiction: {package_name} is AFFECTED "
                        "in the source data but described as not affected."
                    )
                elif status == "NOT_AFFECTED" and re.search(
                    r"\b(?:affected|vulnerable)\b", package_context
                ) and not re.search(
                    r"\b(?:not affected|unaffected|not vulnerable)\b",
                    package_context,
                ):
                    warnings.append(
                        f"Package status contradiction: {package_name} is NOT_AFFECTED "
                        "in the source data but described as affected."
                    )

                for fixed_version in package.get("fixed_versions", []) or []:
                    version_pattern = re.compile(
                        rf"(?<![\w.]){re.escape(str(fixed_version))}(?![\w.])",
                        re.IGNORECASE,
                    )
                    if not version_pattern.search(package_context):
                        warnings.append(
                            f"Fixed version omitted: OSV supplies {fixed_version} "
                            f"for {package_name}; see the deterministic recommendation."
                        )

                # If the explanation names a fix or upgrade version, ensure
                # it is one of OSV's fixes (or the supplied installed version).
                fixed_versions = {
                    str(version) for version in package.get("fixed_versions", []) or []
                }
                allowed_versions = fixed_versions | (
                    {str(installed_version)} if installed_version else set()
                )
                fix_cue = re.compile(
                    r"\b(?:fixed|fix|patched|patch|upgrade|upgraded|update|updated)\b"
                )
                version_token = re.compile(
                    r"(?<![\w.-])v?\d+(?:\.\d+)+(?:[a-z0-9.+-]*)?(?![\w.-])",
                    re.IGNORECASE,
                )
                for sentence in package_sentences:
                    if not fix_cue.search(sentence):
                        continue
                    mentioned_versions = {
                        token.group(0).lstrip("vV")
                        for token in version_token.finditer(sentence)
                    }
                    unsupported_versions = mentioned_versions - allowed_versions
                    if unsupported_versions:
                        warnings.append(
                            "Fixed version contradiction: the explanation gives a fix or "
                            f"upgrade version for {package_name} that OSV does not supply."
                        )
                        break

        # Avoid repeating the same warning when multiple checks detect it.
        return list(dict.fromkeys(warnings))

    @classmethod
    def _blocking_validation_errors(cls, warnings: list[str]) -> list[str]:
        """Return only contradictions that make the generated narrative unsafe to trust."""
        return [
            warning
            for warning in warnings
            if warning.startswith(cls.HARD_VALIDATION_PREFIXES)
        ]


    def explain(self, analysis: dict) -> dict:
        """
        Generate an explanation while preserving the original
        analyzer output as independently verifiable facts.
        """

        self._validate_analysis(analysis)

        verified_facts = {
            "cve_id": copy.deepcopy(analysis.get("cve_id")),
            "description": copy.deepcopy(
                analysis.get("description")
            ),
            "advisories": copy.deepcopy(
                analysis.get("advisories", [])
            ),
            "risk": copy.deepcopy(
                analysis.get("risk", {})
            ),
            "affected_packages": copy.deepcopy(
                analysis.get("affected_packages", [])
            ),
            "recommendations": copy.deepcopy(
                analysis.get("recommendations", [])
            ),
            "installed_package_check_performed": copy.deepcopy(
                analysis.get(
                    "installed_package_check_performed",
                    False,
                )
            ),
        }

        prompt = self._build_prompt(analysis)

        explanation = self.provider.generate(prompt)

        if not isinstance(explanation, str):
            raise TypeError(
                "The LLM provider must return a string"
            )

        if not explanation.strip():
            raise ValueError(
                "The LLM provider returned an empty explanation"
            )
        validation_warnings = self._validate_generated_explanation(
            explanation,
            verified_facts,
        )
        validation_errors = self._blocking_validation_errors(validation_warnings)
        repair_attempts = 0

        if validation_errors:
            repair_attempts = 1
            repair_prompt = (
                prompt
                + "\n\nCORRECTION REQUIRED: Your previous draft contradicted verified facts. "
                + "Regenerate the complete explanation using only the source data above. "
                + "Resolve every validation failure, including score provenance and "
                + "advisory-specific exposure conditions:\n"
                + json.dumps(validation_errors, ensure_ascii=False)
                + "\nDo not say a field is unavailable when its supplied value is present. "
                + "Return only the corrected six-section explanation."
            )
            corrected = self.provider.generate(repair_prompt)
            if isinstance(corrected, str) and corrected.strip():
                explanation = corrected.strip()
                validation_warnings = self._validate_generated_explanation(
                    explanation,
                    verified_facts,
                )
                validation_errors = self._blocking_validation_errors(
                    validation_warnings
                )

        return {
            "cve_id": analysis["cve_id"],
            "explanation": explanation.strip(),
            "risk": copy.deepcopy(analysis.get("risk", {})),
            "affected_packages": copy.deepcopy(
                analysis.get("affected_packages", [])
            ),
            "recommendations": copy.deepcopy(
                analysis.get("recommendations", [])
            ),
            "verified_facts": verified_facts,
            "validation_warnings": validation_warnings,
            "validation_errors": validation_errors,
            "validation_version": 2,
            "repair_attempts": repair_attempts,
            "metadata": {
                "provider": self.provider.__class__.__name__,
                "llm_generated": True,
                "source_data_preserved": True,
            },
        }
