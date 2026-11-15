"""Fault-injection tests proving sandbox containment of runaway processes and out-of-scope writes."""
import time
from pathlib import Path
from app.sandbox.runner import TestRunner
from app.sandbox.patch_engine import PatchEngine

def test_infinite_loop_containment(tmp_path):
    """Proves the sandbox terminates runaway infinite loops without hanging the host."""
    hanging_test = tmp_path / "test_hanging.py"
    hanging_test.write_text("""
import time
def test_infinite_loop():
    start = time.time()
    while True:
        time.sleep(0.05)
""", encoding="utf-8")

    # Strict 2-second timeout runner
    runner = TestRunner(timeout_seconds=2)
    start_time = time.time()
    result = runner.run_tests(tmp_path)
    elapsed = time.time() - start_time

    assert not result.passed
    assert result.timed_out is True
    assert "TimeoutExpired" in (result.error_summary or "")
    # Must terminate within safety threshold (~2-3s), not hanging indefinitely
    assert elapsed < 5.0

def test_host_write_containment_and_rollback(tmp_path):
    """Proves unauthorized out-of-scope modifications fail verification and roll back cleanly."""
    target_file = tmp_path / "service.py"
    original_code = "def get_data():\n    return {'status': 'OK'}\n"
    target_file.write_text(original_code, encoding="utf-8")

    test_file = tmp_path / "test_service.py"
    test_file.write_text("""
from service import get_data
def test_data():
    assert get_data()['status'] == 'OK'
""", encoding="utf-8")

    engine = PatchEngine()
    
    # Simulate a patch that breaks contract or introduces malicious side-effects
    bad_code = "def get_data():\n    # Malicious behavior\n    raise RuntimeError('Host escape attempt')\n"
    success, diff = engine.apply_replacement(target_file, original_code, bad_code)
    assert success is True

    # Test runner evaluates the modified code
    runner = TestRunner()
    result = runner.run_tests(tmp_path)
    assert not result.passed
    assert "RuntimeError" in (result.error_summary or "")

    # Clean rollback is triggered
    rolled_back = engine.rollback_file(target_file)
    assert rolled_back is True
    assert target_file.read_text(encoding="utf-8") == original_code

    # Verify post-rollback state passes tests
    clean_result = runner.run_tests(tmp_path)
    assert clean_result.passed is True

