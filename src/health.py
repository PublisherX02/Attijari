"""health.py — Per-tool health monitoring and maintenance alerts.

Tracks each pipeline tool's performance individually:
  - Success/failure counts and rates
  - Latency (avg, p95, max)
  - Consecutive failure detection
  - Anomaly flagging (latency spikes, error bursts)

Writes maintenance alerts to data/maintenance_alerts.jsonl.
Exposes tool-by-tool status via get_tool_health() for the admin dashboard.

Tools tracked:
  - threatfox, virustotal, abuseipdb, otx (API enrichment)
  - dnstwist, whois (local + RDAP)
  - ollama (LLM inference)
  - database (PostgreSQL)
  - threat_feeds (OpenPhish, URLhaus)
  - extraction (container sandbox)
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_ALERTS_FILE = _DATA_DIR / "maintenance_alerts.jsonl"

# Alert logger — separate from audit trail
_alert_logger = logging.getLogger("tijari.health.alerts")
_alert_handler = logging.FileHandler(_ALERTS_FILE, encoding="utf-8")
_alert_handler.setFormatter(logging.Formatter("%(message)s"))
_alert_logger.addHandler(_alert_handler)
_alert_logger.setLevel(logging.WARNING)
_alert_logger.propagate = False

# Thresholds
CONSECUTIVE_FAIL_THRESHOLD = 3       # alert after N consecutive failures
LATENCY_SPIKE_MULTIPLIER = 3.0       # alert if latency > 3x rolling average
ERROR_RATE_THRESHOLD = 0.5           # alert if error rate > 50% in window
LATENCY_WINDOW_SIZE = 50             # rolling window for latency stats
MIN_SAMPLES_FOR_ANOMALY = 5          # need at least N samples before anomaly detection


@dataclass
class ToolStats:
    """Per-tool performance statistics."""
    name: str
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_success: float | None = None       # unix timestamp
    last_failure: float | None = None
    last_error: str | None = None
    last_latency: float | None = None
    _latencies: deque = field(default_factory=lambda: deque(maxlen=LATENCY_WINDOW_SIZE))
    _recent_errors: deque = field(default_factory=lambda: deque(maxlen=20))

    @property
    def total_calls(self) -> int:
        return self.success_count + self.failure_count

    @property
    def error_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.failure_count / self.total_calls

    @property
    def avg_latency(self) -> float | None:
        if not self._latencies:
            return None
        return sum(self._latencies) / len(self._latencies)

    @property
    def p95_latency(self) -> float | None:
        if len(self._latencies) < 2:
            return None
        sorted_l = sorted(self._latencies)
        idx = int(len(sorted_l) * 0.95)
        return sorted_l[min(idx, len(sorted_l) - 1)]

    @property
    def max_latency(self) -> float | None:
        if not self._latencies:
            return None
        return max(self._latencies)

    @property
    def status(self) -> str:
        """Overall tool health status."""
        if self.total_calls == 0:
            return "unknown"
        if self.consecutive_failures >= CONSECUTIVE_FAIL_THRESHOLD:
            return "critical"
        if self.error_rate > ERROR_RATE_THRESHOLD and self.total_calls >= MIN_SAMPLES_FOR_ANOMALY:
            return "degraded"
        if self.consecutive_failures > 0:
            return "warning"
        return "healthy"

    def to_dict(self) -> dict[str, Any]:
        now = time.time()
        return {
            "name": self.name,
            "status": self.status,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "total_calls": self.total_calls,
            "error_rate": round(self.error_rate, 3),
            "consecutive_failures": self.consecutive_failures,
            "avg_latency_s": round(self.avg_latency, 3) if self.avg_latency is not None else None,
            "p95_latency_s": round(self.p95_latency, 3) if self.p95_latency is not None else None,
            "max_latency_s": round(self.max_latency, 3) if self.max_latency is not None else None,
            "last_latency_s": round(self.last_latency, 3) if self.last_latency is not None else None,
            "last_success_ago_s": round(now - self.last_success, 1) if self.last_success else None,
            "last_failure_ago_s": round(now - self.last_failure, 1) if self.last_failure else None,
            "last_error": self.last_error,
            "recent_errors": list(self._recent_errors),
        }


_STATS_FILE = _DATA_DIR / "health_stats.json"
_SAVE_INTERVAL = 30  # seconds between disk flushes


class HealthMonitor:
    """Singleton health monitor tracking all pipeline tools."""

    # All tracked tools
    TOOLS = (
        "threatfox", "virustotal", "abuseipdb", "otx",
        "dnstwist", "whois", "ollama", "database",
        "threat_feeds", "extraction",
    )

    def __init__(self):
        self._lock = threading.Lock()
        self._tools: dict[str, ToolStats] = {name: ToolStats(name=name) for name in self.TOOLS}
        self._started = time.time()
        self._last_save = 0.0
        self._load_from_disk()

    def _load_from_disk(self):
        """Restore persisted stats on startup."""
        try:
            if not _STATS_FILE.exists():
                return
            data = json.loads(_STATS_FILE.read_text(encoding="utf-8"))
            for name, saved in data.items():
                stats = self._tools.get(name)
                if not stats:
                    stats = ToolStats(name=name)
                    self._tools[name] = stats
                stats.success_count = saved.get("success_count", 0)
                stats.failure_count = saved.get("failure_count", 0)
                stats.consecutive_failures = saved.get("consecutive_failures", 0)
                stats.last_success = saved.get("last_success")
                stats.last_failure = saved.get("last_failure")
                stats.last_error = saved.get("last_error")
                stats.last_latency = saved.get("last_latency")
                for lat in saved.get("latencies", []):
                    stats._latencies.append(lat)
                for err in saved.get("recent_errors", []):
                    stats._recent_errors.append(err)
        except Exception:
            pass  # corrupted file — start fresh

    def _save_to_disk(self):
        """Persist current stats to JSON file."""
        data = {}
        for name, stats in self._tools.items():
            if stats.total_calls == 0:
                continue
            data[name] = {
                "success_count": stats.success_count,
                "failure_count": stats.failure_count,
                "consecutive_failures": stats.consecutive_failures,
                "last_success": stats.last_success,
                "last_failure": stats.last_failure,
                "last_error": stats.last_error,
                "last_latency": stats.last_latency,
                "latencies": list(stats._latencies),
                "recent_errors": list(stats._recent_errors),
            }
        try:
            _STATS_FILE.write_text(json.dumps(data, default=str), encoding="utf-8")
            self._last_save = time.time()
        except Exception:
            pass

    def _maybe_save(self):
        """Flush to disk if enough time has passed since last save."""
        if time.time() - self._last_save >= _SAVE_INTERVAL:
            self._save_to_disk()

    def record_success(self, tool: str, latency: float):
        """Record a successful tool call."""
        with self._lock:
            stats = self._tools.get(tool)
            if not stats:
                stats = ToolStats(name=tool)
                self._tools[tool] = stats

            stats.success_count += 1
            stats.consecutive_failures = 0
            stats.last_success = time.time()
            stats.last_latency = latency
            stats._latencies.append(latency)

            # Check for latency spike
            if (len(stats._latencies) >= MIN_SAMPLES_FOR_ANOMALY
                    and stats.avg_latency is not None
                    and latency > stats.avg_latency * LATENCY_SPIKE_MULTIPLIER):
                self._emit_alert(
                    tool=tool,
                    alert_type="latency_spike",
                    severity="warning",
                    message=f"{tool} latency spike: {latency:.2f}s (avg: {stats.avg_latency:.2f}s)",
                    data={"latency": latency, "avg": stats.avg_latency},
                )

            self._maybe_save()

    def record_failure(self, tool: str, error: str, latency: float | None = None):
        """Record a failed tool call."""
        with self._lock:
            stats = self._tools.get(tool)
            if not stats:
                stats = ToolStats(name=tool)
                self._tools[tool] = stats

            stats.failure_count += 1
            stats.consecutive_failures += 1
            stats.last_failure = time.time()
            stats.last_error = error
            stats._recent_errors.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "error": error[:200],
            })
            if latency is not None:
                stats.last_latency = latency
                stats._latencies.append(latency)

            # Consecutive failure alert
            if stats.consecutive_failures == CONSECUTIVE_FAIL_THRESHOLD:
                self._emit_alert(
                    tool=tool,
                    alert_type="consecutive_failures",
                    severity="critical",
                    message=f"{tool} has failed {stats.consecutive_failures} times consecutively",
                    data={"consecutive": stats.consecutive_failures, "last_error": error[:200]},
                )

            # Error rate alert
            if (stats.total_calls >= MIN_SAMPLES_FOR_ANOMALY
                    and stats.error_rate > ERROR_RATE_THRESHOLD):
                self._emit_alert(
                    tool=tool,
                    alert_type="high_error_rate",
                    severity="warning",
                    message=f"{tool} error rate: {stats.error_rate:.0%} ({stats.failure_count}/{stats.total_calls})",
                    data={"error_rate": stats.error_rate, "total": stats.total_calls},
                )

            self._maybe_save()

    def record_false_negative(self, tool: str, indicator: str, details: str = ""):
        """Record a known false negative — an indicator the tool should have caught."""
        with self._lock:
            self._emit_alert(
                tool=tool,
                alert_type="false_negative",
                severity="critical",
                message=f"{tool} false negative: missed {indicator}",
                data={"indicator": indicator, "details": details},
            )

    def get_tool_health(self, tool: str) -> dict[str, Any] | None:
        """Get health stats for a single tool."""
        with self._lock:
            stats = self._tools.get(tool)
            return stats.to_dict() if stats else None

    def get_all_health(self) -> dict[str, Any]:
        """Get health overview for all tools."""
        with self._lock:
            tools = {name: stats.to_dict() for name, stats in self._tools.items()}

        # Overall system status
        statuses = [t["status"] for t in tools.values()]
        if "critical" in statuses:
            overall = "critical"
        elif "degraded" in statuses:
            overall = "degraded"
        elif "warning" in statuses:
            overall = "warning"
        elif all(s == "unknown" for s in statuses):
            overall = "unknown"
        else:
            overall = "healthy"

        return {
            "overall_status": overall,
            "uptime_s": round(time.time() - self._started, 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": tools,
        }

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Read recent alerts from the alert log file."""
        alerts = []
        try:
            if _ALERTS_FILE.exists():
                lines = _ALERTS_FILE.read_text(encoding="utf-8").strip().splitlines()
                for line in lines[-limit:]:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        alerts.reverse()  # newest first
        return alerts

    def _emit_alert(self, tool: str, alert_type: str, severity: str,
                    message: str, data: dict | None = None):
        """Write a maintenance alert."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
        }
        if data:
            record["data"] = data
        try:
            _alert_logger.warning(json.dumps(record, default=str, ensure_ascii=False))
        except Exception:
            pass  # health monitoring must never crash the pipeline
        # Also print to console for operator visibility
        print(f"[HEALTH-ALERT] [{severity.upper()}] {message}")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_monitor: HealthMonitor | None = None
_monitor_lock = threading.Lock()


def get_monitor() -> HealthMonitor:
    """Get the singleton HealthMonitor instance."""
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = HealthMonitor()
    return _monitor


# ---------------------------------------------------------------------------
# Convenience functions (used by enrichment.py and main.py)
# ---------------------------------------------------------------------------

def record_success(tool: str, latency: float):
    get_monitor().record_success(tool, latency)


def record_failure(tool: str, error: str, latency: float | None = None):
    get_monitor().record_failure(tool, error, latency)


def record_false_negative(tool: str, indicator: str, details: str = ""):
    get_monitor().record_false_negative(tool, indicator, details)
