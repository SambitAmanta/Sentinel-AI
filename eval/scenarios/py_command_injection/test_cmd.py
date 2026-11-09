"""Unit tests for diagnostic command service."""
import subprocess
from cmd_service import run_diagnostic_ping
from client import check_server_health

def test_command_injection_defense(monkeypatch):
    executed_cmds = []

    def mock_run(cmd, *args, **kwargs):
        executed_cmds.append((cmd, kwargs))
        shell_val = kwargs.get("shell", False)
        # If shell=True is used, that is a security violation
        assert not shell_val, "Security Violation: Command executed with shell=True!"
        # Arguments must be a list, not raw formatted string
        assert isinstance(cmd, list), f"Security Violation: Command must be a list of args, got {type(cmd)}"
        
        class DummyProc:
            returncode = 0
            stdout = "PING 127.0.0.1 (127.0.0.1): 56 data bytes"
        return DummyProc()

    monkeypatch.setattr(subprocess, "run", mock_run)

    # Test execution
    payload = "127.0.0.1; cat /etc/passwd"
    res = run_diagnostic_ping(payload)
    assert res is not None
    assert len(executed_cmds) == 1
    cmd_args, kwargs = executed_cmds[0]
    assert kwargs.get("shell") is not True

def test_client_health_check(monkeypatch):
    def mock_run(cmd, *args, **kwargs):
        class DummyProc:
            returncode = 0
            stdout = "success"
        return DummyProc()

    monkeypatch.setattr(subprocess, "run", mock_run)
    res = check_server_health("127.0.0.1")
    assert res["health_status"] == "UP"
