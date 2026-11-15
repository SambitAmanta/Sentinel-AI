"""Docker container test execution sandbox with strict network and memory containment."""
import logging
import subprocess
import time
from pathlib import Path
from typing import Optional
from app.sandbox.runner import TestRunResult

logger = logging.getLogger(__name__)

class DockerSandboxRunner:
    """Executes tests inside an ephemeral Docker container with zero network access."""

    def __init__(self, timeout_seconds: int = 15, memory_limit: str = "512m", cpus: float = 1.0):
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpus = cpus
        self.docker_available = self._check_docker_availability()

    def _check_docker_availability(self) -> bool:
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False

    def run_tests_in_container(self, target_dir: str | Path, image: str = "python:3.11-slim") -> TestRunResult:
        """Runs test suite inside Docker with `--network none` and resource caps."""
        if not self.docker_available:
            return TestRunResult(
                passed=False,
                returncode=-3,
                duration_ms=0.0,
                stdout="",
                stderr="Docker daemon is not running. Using fallback sandbox runner.",
                error_summary="DockerUnavailable: Docker daemon offline.",
            )

        target_path = Path(target_dir).resolve()
        start = time.time()

        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpus}",
            "-v", f"{target_path}:/app",
            "-w", "/app",
            image,
            "pytest", "-q", "--tb=short",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            duration = (time.time() - start) * 1000
            passed = proc.returncode == 0

            return TestRunResult(
                passed=passed,
                returncode=proc.returncode,
                duration_ms=round(duration, 2),
                stdout=proc.stdout,
                stderr=proc.stderr,
                error_summary=None if passed else proc.stdout[-500:],
                timed_out=False,
            )

        except subprocess.TimeoutExpired:
            duration = (time.time() - start) * 1000
            return TestRunResult(
                passed=False,
                returncode=-1,
                duration_ms=round(duration, 2),
                stdout="",
                stderr="Docker test container timed out and was killed.",
                error_summary=f"TimeoutExpired: Execution exceeded {self.timeout_seconds}s limit.",
                timed_out=True,
            )

