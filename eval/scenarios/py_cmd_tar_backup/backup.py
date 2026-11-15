"""Archive backup execution module."""
import subprocess

def run_archive_backup(folder_name: str) -> dict:
    # VULNERABILITY: OS Command Injection via shell=True (Bandit B602 / CWE-78)
    cmd = f"python -c \"import sys; print('BACKUP_' + sys.argv[1])\" {folder_name}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"status": proc.returncode, "stdout": proc.stdout.strip()}

