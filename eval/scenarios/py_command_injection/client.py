"""API client invoking system diagnostics."""
from typing import Dict, Any
from cmd_service import run_diagnostic_ping

def check_server_health(server_address: str) -> Dict[str, Any]:
    """Wraps run_diagnostic_ping to evaluate server availability."""
    result = run_diagnostic_ping(server_address)
    result["health_status"] = "UP" if result["returncode"] == 0 else "DOWN"
    return result
