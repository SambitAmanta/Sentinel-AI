"""Native Bandit static security scanner for Python codebases."""
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from app.scanners.schemas import AuditReport, Severity, VulnerabilityFinding
from app.scanners.ast_security_rules import ASTSecurityScanner

logger = logging.getLogger(__name__)

# Map common Bandit Test IDs to CWE and OWASP
BANDIT_METADATA_MAP = {
    "B608": {"cwe": "CWE-89", "owasp": "A03:2021-Injection", "desc": "Possible SQL injection vector through string formatting."},
    "B602": {"cwe": "CWE-78", "owasp": "A03:2021-Injection", "desc": "Subprocess call with shell=True detected (Command Injection)."},
    "B605": {"cwe": "CWE-78", "owasp": "A03:2021-Injection", "desc": "Starting a process with a shell, possible injection."},
    "B301": {"cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures", "desc": "Pickle and modules that wrap it can be unsafe when used with untrusted data."},
    "B303": {"cwe": "CWE-327", "owasp": "A02:2021-Cryptographic Failures", "desc": "Use of insecure MD5 or SHA1 hash function."},
    "B105": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures", "desc": "Possible hardcoded password string."},
    "B106": {"cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures", "desc": "Possible hardcoded password argument."},
    "B201": {"cwe": "CWE-94", "owasp": "A03:2021-Injection", "desc": "Flask app run with debug=True detected."},
}

SEVERITY_MAP = {
    "HIGH": Severity.CRITICAL,
    "MEDIUM": Severity.HIGH,
    "LOW": Severity.MEDIUM,
}

class BanditScanner:
    """Executes Bandit static analysis and outputs structured Pydantic findings."""

    def __init__(self, bandit_executable: Optional[str] = None):
        self.ast_scanner = ASTSecurityScanner()
        if bandit_executable:
            self.bandit_exec = bandit_executable
        else:
            venv_bandit = Path(sys.prefix) / "Scripts" / "bandit.exe"
            self.bandit_exec = str(venv_bandit) if venv_bandit.exists() else "bandit"

    def scan_directory(self, target_dir: str | Path) -> AuditReport:
        target_path = Path(target_dir).resolve()
        start_time = time.time()

        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # Run bandit skipping B101 (assert statements in tests)
        cmd = [self.bandit_exec, "-r", str(target_path), "-f", "json", "-q", "-s", "B101"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            stdout = result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out.")
            stdout = "{}"
        except Exception as e:
            logger.error(f"Failed to execute Bandit: {e}")
            stdout = "{}"

        findings: List[VulnerabilityFinding] = []
        files_scanned = 0

        try:
            data = json.loads(stdout) if stdout else {}
            results = data.get("results", [])
            metrics = data.get("metrics", {})
            files_scanned = len([k for k in metrics.keys() if k != "_totals"]) or 1

            for item in results:
                raw_filename = item.get("filename", "")
                file_obj = Path(raw_filename)
                
                # Relative file path
                try:
                    rel_file = str(file_obj.relative_to(target_path))
                except ValueError:
                    rel_file = raw_filename

                # Filter out test suites from vulnerability triage
                if file_obj.name.startswith("test_") or "tests" in Path(rel_file).parts:
                    continue

                test_id = item.get("test_id", "UNKNOWN")
                meta = BANDIT_METADATA_MAP.get(test_id, {})
                cwe_id = meta.get("cwe") or item.get("issue_cwe", {}).get("id")
                if cwe_id and not str(cwe_id).startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"

                severity_str = item.get("issue_severity", "MEDIUM").upper()
                mapped_severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

                finding = VulnerabilityFinding(
                    id=f"VULN-{len(findings) + 1:03d}",
                    check_id=f"bandit.{test_id}",
                    cwe_id=cwe_id,
                    owasp_category=meta.get("owasp"),
                    severity=mapped_severity,
                    file_path=rel_file,
                    line_start=item.get("line_number", 1),
                    line_end=item.get("line_range", [item.get("line_number", 1)])[-1],
                    message=item.get("issue_text", "Security issue detected"),
                    code_snippet=item.get("code", "").strip(),
                )
                findings.append(finding)
        except Exception as e:
            logger.error(f"Error parsing Bandit JSON output: {e}")

        # AST-level static security scan for CWE-22, CWE-95, etc.
        try:
            for py_file in target_path.rglob("*.py"):
                if "test_" in py_file.name or "tests" in py_file.parts or ".venv" in py_file.parts:
                    continue
                try:
                    rel_f = str(py_file.relative_to(target_path))
                except ValueError:
                    rel_f = str(py_file)
                ast_findings = self.ast_scanner.scan_file(py_file, rel_f)
                for af in ast_findings:
                    af.id = f"VULN-{len(findings) + 1:03d}"
                    findings.append(af)
        except Exception as e:
            logger.error(f"Error during AST security scanning: {e}")

        duration = (time.time() - start_time) * 1000
        report = AuditReport(
            repository_path=str(target_path),
            total_files_scanned=files_scanned,
            findings=findings,
            scan_duration_ms=round(duration, 2),
        )
        report.compute_summary()
        return report
