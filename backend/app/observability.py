"""Local telemetry and observability tracking for SentinelAI agent runs."""
import json
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Dict, Any, Optional

@dataclass
class AuditTelemetryRecord:
    audit_id: str
    target_repo: str
    timestamp: float
    total_duration_ms: float
    files_scanned: int
    vulnerabilities_detected: int
    vulnerabilities_resolved: int
    iterations_taken: int
    sandbox_test_duration_ms: float
    status: str

class TelemetryTracker:
    """Records audit telemetry locally with zero cloud dependencies."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path(__file__).resolve().parent.parent / "telemetry_metrics.json"
        self._records: List[AuditTelemetryRecord] = []
        self._load_existing()

    def _load_existing(self):
        if self.storage_path.exists():
            try:
                data = json.loads(self.storage_path.read_text(encoding="utf-8"))
                for item in data:
                    self._records.append(AuditTelemetryRecord(**item))
            except Exception:
                pass

    def record_run(
        self,
        audit_id: str,
        target_repo: str,
        duration_ms: float,
        files_scanned: int,
        detected: int,
        resolved: int,
        iterations: int,
        sandbox_time_ms: float,
        status: str,
    ):
        record = AuditTelemetryRecord(
            audit_id=audit_id,
            target_repo=target_repo,
            timestamp=time.time(),
            total_duration_ms=round(duration_ms, 2),
            files_scanned=files_scanned,
            vulnerabilities_detected=detected,
            vulnerabilities_resolved=resolved,
            iterations_taken=iterations,
            sandbox_test_duration_ms=round(sandbox_time_ms, 2),
            status=status,
        )
        self._records.append(record)
        self._persist()

    def _persist(self):
        try:
            data = [asdict(r) for r in self._records]
            self.storage_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get_summary(self) -> Dict[str, Any]:
        if not self._records:
            return {
                "total_audits": 0,
                "mean_duration_ms": 0.0,
                "resolution_rate": 100.0,
                "total_vulnerabilities_fixed": 0,
            }

        total = len(self._records)
        mean_dur = sum(r.total_duration_ms for r in self._records) / total
        total_detected = sum(r.vulnerabilities_detected for r in self._records)
        total_resolved = sum(r.vulnerabilities_resolved for r in self._records)
        rate = (total_resolved / total_detected * 100) if total_detected > 0 else 100.0

        return {
            "total_audits": total,
            "mean_duration_ms": round(mean_dur, 2),
            "resolution_rate": round(rate, 1),
            "total_vulnerabilities_fixed": total_resolved,
            "records": [asdict(r) for r in self._records[-10:]],
        }

telemetry = TelemetryTracker()

