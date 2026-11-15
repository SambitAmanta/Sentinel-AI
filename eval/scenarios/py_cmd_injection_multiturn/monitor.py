"""System monitor consuming telemetry."""
from typing import Dict, Any
from system import get_system_stats

def collect_health_metrics() -> Dict[str, Any]:
    res = get_system_stats("UPTIME")
    if not res["output"].startswith("METRIC_"):
        raise ValueError("Invalid metric format")
    return {"status": "HEALTHY", "raw": res["output"]}

