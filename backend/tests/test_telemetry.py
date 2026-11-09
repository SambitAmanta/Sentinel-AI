"""Unit tests for local telemetry tracker."""
from pathlib import Path
from app.observability import TelemetryTracker

def test_telemetry_recording(tmp_path):
    storage_file = tmp_path / "metrics.json"
    tracker = TelemetryTracker(storage_path=storage_file)

    tracker.record_run(
        audit_id="test-run-001",
        target_repo="test_repo",
        duration_ms=1250.0,
        files_scanned=5,
        detected=2,
        resolved=2,
        iterations=1,
        sandbox_time_ms=950.0,
        status="COMPLETED",
    )

    summary = tracker.get_summary()
    assert summary["total_audits"] == 1
    assert summary["resolution_rate"] == 100.0
    assert summary["total_vulnerabilities_fixed"] == 2
    assert summary["mean_duration_ms"] == 1250.0
