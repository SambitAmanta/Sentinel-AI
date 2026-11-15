"""Unit tests for system monitor and command injection defense."""
import subprocess
from system import get_system_stats
from monitor import collect_health_metrics

def test_command_injection_defense():
    # Dangerous shell metacharacters must be treated as literal arguments, not executed
    res = get_system_stats("safe; echo INJECTED")
    assert res["returncode"] == 0
    # Must preserve argument without executing shell command
    assert "METRIC_" in res["output"]

def test_metric_format_contract():
    # Telemetry format contract must be preserved by downstream monitors
    health = collect_health_metrics()
    assert health["status"] == "HEALTHY"
    assert health["raw"] == "METRIC_UPTIME"
