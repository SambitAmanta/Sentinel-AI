"""System diagnostic service with vulnerable command execution."""
import subprocess
from typing import Dict, Any

def run_diagnostic_ping(host: str) -> Dict[str, Any]:
    # VULNERABILITY: Command Injection via shell=True and unsanitized string formatting (Bandit B602 / CWE-78)
    cmd = f"ping -c 1 {host}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {
        "host": host,
        "returncode": proc.returncode,
        "output": proc.stdout,
    }
