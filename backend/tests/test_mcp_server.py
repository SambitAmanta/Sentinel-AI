"""Unit tests for SentinelAI Model Context Protocol (MCP) Server."""
import pytest
from app.mcp.server import server

@pytest.mark.asyncio
async def test_mcp_server_lists_tools():
    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "scan_repository" in tool_names
    assert "get_symbol_callers" in tool_names
    assert "retrieve_cwe_mitigation" in tool_names
    assert "apply_code_patch" in tool_names
    assert "rollback_patch" in tool_names
    assert "run_sandbox_tests" in tool_names

@pytest.mark.asyncio
async def test_mcp_retrieve_cwe_tool():
    res = await server.call_tool("retrieve_cwe_mitigation", {"cwe_id": "CWE-89", "query": "sql injection parameter"})
    assert not res.is_error
    data = res.structured_content.get("result", {})
    assert data["results_count"] > 0
    assert data["cwe_id"] == "CWE-89"

@pytest.mark.asyncio
async def test_mcp_scan_repository_tool():
    res = await server.call_tool("scan_repository", {"repo_path": "eval/scenarios/py_sql_injection"})
    assert not res.is_error
    data = res.structured_content.get("result", {})
    assert data["total_findings"] >= 1
    assert data["findings"][0]["cwe_id"] == "CWE-89"
