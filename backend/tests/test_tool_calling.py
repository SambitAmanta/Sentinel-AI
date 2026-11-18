"""Unit tests for Dynamic LLM Tool Calling."""
from pathlib import Path
from app.agent.tool_calling_agent import ToolCallingAgent, TOOL_DEFINITIONS

def test_tool_definitions_schema():
    assert len(TOOL_DEFINITIONS) >= 5
    names = [t["function"]["name"] for t in TOOL_DEFINITIONS]
    assert "get_symbol_callers" in names
    assert "retrieve_cwe_mitigation" in names
    assert "apply_code_patch" in names
    assert "run_sandbox_tests" in names
    assert "conclude_audit" in names

    for t in TOOL_DEFINITIONS:
        fn = t["function"]
        assert "description" in fn
        assert "parameters" in fn
        assert "properties" in fn["parameters"]

def test_tool_calling_agent_local_execution():
    agent = ToolCallingAgent()
    repo = Path("eval/scenarios/py_sql_injection").resolve()

    # Test tool 1: RAG
    rag_out = agent.execute_tool("retrieve_cwe_mitigation", {"cwe_id": "CWE-89", "query": "sqlite parameterized"}, repo)
    assert rag_out["results_count"] > 0

    # Test tool 2: Callers
    callers_out = agent.execute_tool("get_symbol_callers", {"file_path": "app.py", "line_number": 22}, repo)
    assert "callers" in callers_out

    # Test tool 3: Sandbox
    test_out = agent.execute_tool("run_sandbox_tests", {"repo_path": str(repo)}, repo)
    assert "passed" in test_out
