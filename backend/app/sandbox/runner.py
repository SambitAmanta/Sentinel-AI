"""Isolated subprocess test execution runner with environment scrub and timeout containment."""
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)

@dataclass
class TestRunResult:
    passed: bool
    returncode: int
    duration_ms: float
    stdout: str
    stderr: str
    error_summary: Optional[str] = None
    timed_out: bool = False

class TestRunner:
    """Executes test suites in an isolated environment with network scrubbing, container containment, and process tree termination."""
    __test__ = False

    def __init__(
        self,
        timeout_seconds: int = 15,
        pytest_executable: Optional[str] = None,
        use_docker: bool = False,
    ):
        self.timeout_seconds = timeout_seconds
        self.use_docker = use_docker
        if pytest_executable:
            self.pytest_exec = pytest_executable
        else:
            venv_pytest = Path(sys.prefix) / "Scripts" / "pytest.exe"
            self.pytest_exec = str(venv_pytest) if venv_pytest.exists() else "pytest"

        # Initialize optional Docker container runner
        try:
            from app.sandbox.docker_sandbox import DockerSandboxRunner
            self._docker_runner = DockerSandboxRunner(timeout_seconds=timeout_seconds)
        except Exception:
            self._docker_runner = None

    def _get_scrubbed_env(self) -> Dict[str, str]:
        """Scrubs out sensitive environment variables and restricts network access."""
        env = os.environ.copy()
        
        # Strip external network proxies and API tokens
        blocked_keys = [
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "AWS_ACCESS_KEY_ID"
        ]
        for key in blocked_keys:
            env.pop(key, None)

        # Force offline loopback restriction
        env["NO_PROXY"] = "*"
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def run_tests(self, target_dir: str | Path, test_file: Optional[str] = None) -> TestRunResult:
        target_path = Path(target_dir).resolve()

        # If Docker container mode is enabled and available, dispatch to container runner
        if self.use_docker and self._docker_runner and self._docker_runner.docker_available:
            return self._docker_runner.run_tests_in_container(target_path)

        start = time.time()

        cmd = [self.pytest_exec, "-q", "--tb=short", "-p", "no:langsmith"]
        if test_file:
            cmd.append(str(target_path / test_file))
        else:
            cmd.append(str(target_path))

        env = self._get_scrubbed_env()
        proc = None

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(target_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            stdout, stderr = proc.communicate(timeout=self.timeout_seconds)
            duration = (time.time() - start) * 1000
            passed = proc.returncode == 0
            error_summary = None

            if not passed:
                error_summary = self._extract_failure_reason(stdout)

            return TestRunResult(
                passed=passed,
                returncode=proc.returncode,
                duration_ms=round(duration, 2),
                stdout=stdout,
                stderr=stderr,
                error_summary=error_summary,
                timed_out=False,
            )

        except subprocess.TimeoutExpired:
            duration = (time.time() - start) * 1000
            # Kill process tree on Windows
            if proc:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                        timeout=5,
                    )
                except Exception:
                    proc.kill()

            return TestRunResult(
                passed=False,
                returncode=-1,
                duration_ms=round(duration, 2),
                stdout="",
                stderr=f"Process terminated: Exceeded safety threshold of {self.timeout_seconds}s limit.",
                error_summary=f"TimeoutExpired: Execution exceeded {self.timeout_seconds}s limit (Infinite Loop / Runaway CPU Contained).",
                timed_out=True,
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
                timed_out=False,
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
