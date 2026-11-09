"""Direct functional tests for FastAPI route handlers (socket-free)."""
from app.main import health_check, get_audit_status, sessions
from app.agent.state import AgentState

def test_health_check_direct():
    res = health_check()
    assert res["status"] == "healthy"
    assert "SentinelAI" in res["app"]

def test_status_endpoint_direct():
    sessions["mock-session-123"] = {
        "status": "COMPLETED",
        "state": AgentState(repository_path="eval/scenarios/py_sql_injection"),
    }

    res = get_audit_status("mock-session-123")
    assert res["session_id"] == "mock-session-123"
    assert res["status"] == "COMPLETED"
