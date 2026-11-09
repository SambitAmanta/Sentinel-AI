"""Isolated subprocess test execution runner for sandbox verification."""
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class TestRunResult:
    passed: bool
    returncode: int
    duration_ms: float
    stdout: str
    stderr: str
    error_summary: Optional[str] = None

class TestRunner:
    """Executes test suites in an isolated environment with strict timeout guardrails."""

    def __init__(self, timeout_seconds: int = 15, pytest_executable: Optional[str] = None):
        self.timeout_seconds = timeout_seconds
        # Use active venv python/pytest if available
        if pytest_executable:
            self.pytest_exec = pytest_executable
        else:
            venv_pytest = Path(sys.prefix) / "Scripts" / "pytest.exe"
            self.pytest_exec = str(venv_pytest) if venv_pytest.exists() else "pytest"

    def run_tests(self, target_dir: str | Path, test_file: Optional[str] = None) -> TestRunResult:
        target_path = Path(target_dir).resolve()
        start = time.time()

        cmd = [self.pytest_exec, "-q", "--tb=short"]
        if test_file:
            cmd.append(str(target_path / test_file))
        else:
            cmd.append(str(target_path))

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(target_path),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            duration = (time.time() - start) * 1000
            passed = proc.returncode == 0
            error_summary = None

            if not passed:
                error_summary = self._extract_failure_reason(proc.stdout)

            return TestRunResult(
                passed=passed,
                returncode=proc.returncode,
                duration_ms=round(duration, 2),
                stdout=proc.stdout,
                stderr=proc.stderr,
                error_summary=error_summary,
            )

        except subprocess.TimeoutExpired:
            duration = (time.time() - start) * 1000
            return TestRunResult(
                passed=False,
                returncode=-1,
                duration_ms=round(duration, 2),
                stdout="",
                stderr="Test run timed out after guardrail threshold.",
                error_summary=f"TimeoutExpired: Test execution exceeded {self.timeout_seconds}s limit.",
            )
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestRunResult(
                passed=False,
                returncode=-2,
                duration_ms=round(duration, 2),
                stdout="",
                stderr=str(e),
                error_summary=f"ExecutionError: {e}",
            )

    def _extract_failure_reason(self, output: str) -> str:
        """Parses short pytest output for the exact assertion or syntax failure."""
        lines = output.splitlines()
        failures = []
        for line in lines:
            line_str = line.strip()
            if line_str.startswith("E   ") or "AssertionError" in line_str or "SyntaxError" in line_str:
                failures.append(line_str)
            elif "FAILED" in line_str:
                failures.append(line_str)

        if failures:
            return "\n".join(failures[:5])
        return output[-500:] if len(output) > 500 else output

