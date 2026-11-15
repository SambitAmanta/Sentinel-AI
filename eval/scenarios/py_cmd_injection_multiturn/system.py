"""System telemetry service with command execution vulnerability."""
import subprocess
from typing import Dict, Any

def get_system_stats(metric_name: str) -> Dict[str, Any]:
    # VULNERABILITY: Command Injection via shell=True (Bandit B602 / CWE-78)
    cmd = f"python -c \"import sys; print('METRIC_' + '{metric_name}')\""
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {
        "metric": metric_name,
        "output": proc.stdout.strip(),
        "returncode": proc.returncode,
    }

