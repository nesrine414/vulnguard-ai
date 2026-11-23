
import json
import os

from dotenv import load_dotenv
from confluent_kafka import Consumer, KafkaError, KafkaException

from src.database.db import (
    initialize_database,
    mark_scan_failed,
    save_scan_test_plan,
    save_scan_analysis_result,
    save_scan_event,
    update_scan_status,
    get_scan_status,
)
from src.services.analysis_service import AnalysisService
from src.services.enrichment_adapter import EnrichmentAdapter
from src.services.risk_scoring_adapter import RiskScoringAdapter
from src.streaming.producer import publish_scan_error

from src.agents.llm.ollama_provider import OllamaProvider
from src.agents.llm_explanation import LLMExplanationAgent
from src.agents.security_test_generator import SecurityTestGenerator


load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
)
KAFKA_TOPIC_SCAN_REQUESTS = os.getenv(
    "KAFKA_TOPIC_SCAN_REQUESTS", "scan-requests"
)
KAFKA_GROUP_ID = os.getenv(
    "KAFKA_GROUP_ID", "vulnguard-scan-consumer-dev"
)
KAFKA_MAX_POLL_INTERVAL_MS = os.getenv(
    "KAFKA_MAX_POLL_INTERVAL_MS", "900000"
)


def build_consumer_config() -> dict:
    """Build Kafka settings with room for slow local LLM analysis."""
    try:
        max_poll_interval_ms = int(KAFKA_MAX_POLL_INTERVAL_MS)
    except ValueError as exc:
        raise ValueError(
            "KAFKA_MAX_POLL_INTERVAL_MS must be a positive integer."
        ) from exc
    if max_poll_interval_ms <= 0:
        raise ValueError(
            "KAFKA_MAX_POLL_INTERVAL_MS must be a positive integer."
        )

    return {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": KAFKA_GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "max.poll.interval.ms": max_poll_interval_ms,
    }


def process_scan_event(event):
    """Display basic information about the received scan."""
    print("\n========== NEW SCAN EVENT ==========")
    print(f"Scan ID: {event.get('scan_id')}")
    print(f"Project: {event.get('project_name', 'N/A')}")
    print(f"Dependencies: {len(event.get('dependencies', []))}")
    print("====================================\n")


def analyze_scan_event(event, analysis_service):
    """
    Analyze a scan and persist the complete analysis result.

    The workflow generates vulnerability findings, risk assessments,
    LLM explanations and security test plans.

    Test plans remain pending human approval.
    No security test is executed here.
    """
    scan_id = event.get("scan_id")

    if not scan_id:
        raise ValueError("Missing scan_id in scan event.")

    current_status = get_scan_status(scan_id)

    if current_status is None:
        save_scan_event(event)
        update_scan_status(scan_id, "RECEIVED")
        current_status = "RECEIVED"

    if current_status == "RECEIVED":
        update_scan_status(scan_id, "WAITING_ANALYSIS")
        current_status = "WAITING_ANALYSIS"

    if current_status != "WAITING_ANALYSIS":
        print(
            f"Scan {scan_id} skipped: "
            f"current status is {current_status}."
        )
        return {
            "scan_id": scan_id,
            "status": current_status,
            "skipped": True,
        }

    process_scan_event(event)

    try:
        result = analysis_service.analyze_with_security_workflow(
            scan_id=scan_id,
            dependencies=event.get("dependencies", []),
        )

        result_data = result.to_dict()

        plans = result_data.get("security_test_plans", [])
        reports = result_data.get("final_reports", [])
        for plan, report in zip(plans, reports):
            plan["final_report"] = report
            save_scan_test_plan(
                scan_id,
                plan["cve_id"],
                plan,
            )

        # Persist all analysis outputs in SQLite.
        save_scan_analysis_result(scan_id, result_data)

        update_scan_status(
            scan_id,
            "ANALYZED",
            (
                "Full security analysis completed: "
                f"{len(result_data.get('vulnerabilities', []))} "
                "vulnerability findings."
            ),
        )

        return result_data

    except Exception as exc:
        mark_scan_failed(scan_id, str(exc))
        raise


def report_scan_error(event, error_message):
    """Publish an error to the scan error topic."""
    try:
        publish_scan_error(
            scan_id=event.get("scan_id") if isinstance(event, dict) else None,
            error_message=error_message,
            raw_payload=event,
        )
    except Exception as publish_error:
        print(f"Could not publish scan error: {publish_error}")


def start_consumer():
    """Start the Kafka consumer and process scan requests."""
    initialize_database()

    ollama = OllamaProvider()
    if ollama.is_available():
        print("Ollama is available — LLM explanations enabled.")
        llm_explainer = LLMExplanationAgent(provider=ollama)
    else:
        print(
            "WARNING: Ollama is unreachable. "
            "Scans will be analyzed without LLM explanations."
        )
        llm_explainer = None

    analysis_service = AnalysisService(
        enrichment_adapter=EnrichmentAdapter.from_intelligence_engine(),
        risk_scorer=RiskScoringAdapter(),
        llm_explainer=llm_explainer,
        test_generator=SecurityTestGenerator(),
    )

    consumer_config = build_consumer_config()

    consumer = Consumer(consumer_config)
    consumer.subscribe([KAFKA_TOPIC_SCAN_REQUESTS])

    print("VulnGuard AI consumer started.")
    print(f"Kafka topic: {KAFKA_TOPIC_SCAN_REQUESTS}")
    print(f"Kafka broker: {KAFKA_BOOTSTRAP_SERVERS}")
    print(
        "Maximum Kafka poll interval: "
        f"{consumer_config['max.poll.interval.ms']} ms"
    )

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue

                raise KafkaException(msg.error())

            event = None

            try:
                raw_payload = msg.value().decode("utf-8")
                event = json.loads(raw_payload)

                if not isinstance(event, dict):
                    raise ValueError(
                        "Scan event must be a JSON object."
                    )

                if not event.get("scan_id"):
                    raise ValueError(
                        "Scan event is missing scan_id."
                    )

                # Save the incoming event before analysis.
                if get_scan_status(event["scan_id"]) is None:
                    save_scan_event(event)
                    update_scan_status(event["scan_id"], "RECEIVED")

                result = analyze_scan_event(
                    event=event,
                    analysis_service=analysis_service,
                )

                if result is not None:
                    print("\n========== FULL SECURITY ANALYSIS ==========")
                    print(
                        "Vulnerability findings: "
                        f"{len(result.get('vulnerabilities', []))}"
                    )

                    risk_data = result.get("risk_assessment") or {}
                    print(
                        "Risk assessments: "
                        f"{len(risk_data.get('assessments', []))}"
                    )

                    print(
                        "LLM explanations: "
                        f"{len(result.get('llm_explanations', []))}"
                    )

                    print(
                        "Security test plans: "
                        f"{len(result.get('security_test_plans', []))}"
                    )

                    print("Test plans require human approval.")
                    print("No tests were automatically executed.")
                    print("Analysis results saved in SQLite.")
                    print("============================================\n")

                # Commit only after processing and persistence.
                consumer.commit(message=msg, asynchronous=False)

            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"Invalid JSON scan payload: {exc}")
                report_scan_error(
                    event if event is not None else msg.value(),
                    str(exc),
                )
                consumer.commit(message=msg, asynchronous=False)

            except ValueError as exc:
                print(f"Invalid scan event: {exc}")
                report_scan_error(
                    event if event is not None else msg.value(),
                    str(exc),
                )
                consumer.commit(message=msg, asynchronous=False)

            except Exception as exc:
                print(f"Error processing scan: {exc}")

                scan_id = event.get("scan_id") if isinstance(event, dict) else None

                if scan_id:
                    try:
                        if get_scan_status(scan_id) == "FAILED":
                            report_scan_error(event, str(exc))
                            consumer.commit(
                                message=msg,
                                asynchronous=False,
                            )
                            continue
                    except Exception as status_error:
                        print(
                            f"Could not retrieve scan status: "
                            f"{status_error}"
                        )

                # Do not commit if the failure was not persisted.
                raise

    except KeyboardInterrupt:
        print("\nConsumer interrupted by user.")

    finally:
        consumer.close()
        print("Kafka consumer closed.")


if __name__ == "__main__":
    start_consumer()
