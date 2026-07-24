"""metrics.py — Prometheus telemetry for the Attijari triage pipeline.

Exposes counters, histograms, and gauges that can be scraped by Prometheus
and visualized in Grafana.

Usage:
  - Import the metric objects where needed and call .observe() / .inc()
  - The /metrics endpoint in api.py exposes them in Prometheus text format
"""
from __future__ import annotations

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Use a custom registry to avoid conflicts with default metrics
REGISTRY = CollectorRegistry()

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

emails_processed_total = Counter(
    "attijari_emails_processed_total",
    "Total emails processed by the pipeline",
    labelnames=["status"],
    registry=REGISTRY,
)

api_requests_total = Counter(
    "attijari_api_requests_total",
    "Total API requests to the dashboard",
    labelnames=["method", "endpoint", "status_code"],
    registry=REGISTRY,
)

blocklist_changes_total = Counter(
    "attijari_blocklist_changes_total",
    "Total blocklist additions/removals",
    labelnames=["action", "indicator_type"],
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

pipeline_duration_seconds = Histogram(
    "attijari_pipeline_duration_seconds",
    "End-to-end pipeline execution time",
    buckets=[1, 5, 10, 30, 60, 120, 300],
    registry=REGISTRY,
)

llm_inference_seconds = Histogram(
    "attijari_llm_inference_seconds",
    "LLM (Ollama) inference time per email",
    buckets=[1, 3, 5, 10, 20, 30, 60, 120],
    registry=REGISTRY,
)

api_enrichment_seconds = Histogram(
    "attijari_api_enrichment_seconds",
    "External API enrichment call latency",
    labelnames=["service"],
    buckets=[0.1, 0.5, 1, 2, 5, 10, 15, 30],
    registry=REGISTRY,
)

api_request_duration_seconds = Histogram(
    "attijari_api_request_duration_seconds",
    "Dashboard API request duration",
    labelnames=["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------

blocklist_size = Gauge(
    "attijari_blocklist_size",
    "Current number of active blocklist entries",
    labelnames=["indicator_type"],
    registry=REGISTRY,
)

threat_feed_age_hours = Gauge(
    "attijari_threat_feed_age_hours",
    "Hours since the last threat feed update",
    labelnames=["feed"],
    registry=REGISTRY,
)

emails_in_queue = Gauge(
    "attijari_emails_in_queue",
    "Emails pending analyst review",
    registry=REGISTRY,
)

scheduler_last_run = Gauge(
    "attijari_scheduler_last_run_timestamp",
    "Unix timestamp of last successful pipeline run",
    registry=REGISTRY,
)

ollama_available = Gauge(
    "attijari_ollama_available",
    "Whether the Ollama LLM service is reachable (1=yes, 0=no)",
    registry=REGISTRY,
)

db_connected = Gauge(
    "attijari_db_connected",
    "Whether the database is connected (1=yes, 0=no)",
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# Export helper
# ---------------------------------------------------------------------------

def get_metrics_text() -> tuple[bytes, str]:
    """Generate Prometheus metrics in text format.

    Returns:
        (body_bytes, content_type)
    """
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
