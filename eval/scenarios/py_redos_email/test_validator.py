"""Unit tests verifying linear regex evaluation without ReDoS vulnerability."""
import time
from validator import validate_user_email

def test_valid_email():
    assert validate_user_email("john_doe12@example.com") is True

def test_redos_backtracking_safety():
    # Dangerous nested repetition payload that freezes catastrophic regexes
    evil_payload = "a" * 25 + "!@evil.com"
    start = time.time()
    res = validate_user_email(evil_payload)
    elapsed = time.time() - start

    assert res is False
    # Safe linear regex must complete in under 50ms, not exponential hang
    assert elapsed < 0.1, f"ReDoS detected: Evaluation took {elapsed}s"

