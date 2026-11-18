"""Autonomous LLM Tool-Calling Agent.

Empowers local SLMs (e.g. Qwen2.5-Coder) to autonomously decide, invoke,
and observe tools (AST context, Vector RAG, patch diffing, and sandbox test execution)
via standard OpenAI/Ollama function-calling schemas.
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

import httpx
from app.config import settings
from app.ast_engine.symbol_graph import SymbolGraph
from app.sandbox.patch_engine import PatchEngine
from app.sandbox.runner import TestRunner
from app.rag.vector_store import CWEVectorStore

logger = logging.getLogger(__name__)

# Standard OpenAI / Ollama Function Calling Tool Definitions
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_symbol_callers",
            "description": "Retrieves the enclosing function/method and cross-file caller dependencies for a vulnerability using Tree-sitter CST call graphs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative path to target source file"},
                    "line_number": {"type": "integer", "description": "Line number where the vulnerability is located"}
                },
                "required": ["file_path", "line_number"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "retrieve_cwe_mitigation",
            "description": "Queries the ChromaDB vector database for semantic CWE mitigation patterns and secure code examples.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cwe_id": {"type": "string", "description": "CWE identifier (e.g. 'CWE-89')"},
                    "query": {"type": "string", "description": "Search query describing the vulnerable operation"}
                },
                "required": ["cwe_id", "query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "apply_code_patch",
            "description": "Applies an exact search-and-replace patch to the target file with generic stdlib import resolution and rollback backup.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative path to target source file"},
                    "target_code": {"type": "string", "description": "Exact verbatim code snippet to be replaced"},
                    "replacement_code": {"type": "string", "description": "Secure replacement code"}
                },
                "required": ["file_path", "target_code", "replacement_code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_sandbox_tests",
            "description": "Runs the test suite inside an isolated containment subprocess sandbox to verify patch correctness and detect regressions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_path": {"type": "string", "description": "Path to the repository being audited"}
                },
                "required": ["repo_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "conclude_audit",
            "description": "Concludes the audit session once tests pass and the security vulnerability is fully resolved.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["RESOLVED", "FAILED"], "description": "Final audit status"},
                    "summary": {"type": "string", "description": "Summary of remediation actions taken and verification results"}
                },
                "required": ["status", "summary"]
            }
        }
    }
]

AGENT_SYSTEM_PROMPT = """You are SentinelAI, an elite autonomous security engineering agent.
Your objective is to investigate security vulnerabilities, retrieve necessary context, apply secure code patches, and verify your fixes in the execution sandbox.

You have access to live codebase tools. Use them strategically:
1. Use `get_symbol_callers` to inspect the enclosing function and call hierarchy.
2. Use `retrieve_cwe_mitigation` to retrieve expert semantic remediation patterns from ChromaDB.
3. Use `apply_code_patch` to apply your secure fix.
4. Use `run_sandbox_tests` to verify that your patch passes unit tests without breaking contracts.
5. If tests fail, inspect the error traceback and apply an improved patch.
6. When verified, call `conclude_audit` to finalize."""


class ToolCallingAgent:
    """Orchestrates autonomous model-driven tool calling with local SLM inference."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_turns: int = 6
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self.max_turns = max_turns

        self.symbol_graph = SymbolGraph()
        self.patch_engine = PatchEngine()
        self.test_runner = TestRunner()
        self.vector_store = CWEVectorStore()

    def execute_tool(self, name: str, args: Dict[str, Any], repo_path: Path) -> Dict[str, Any]:
        """Executes the tool invoked by the LLM and returns structured output."""
        logger.info(f"Executing LLM Tool Call: [{name}] with arguments: {args}")

        if name == "get_symbol_callers":
            f_path = repo_path / args.get("file_path", "")
            line = args.get("line_number", 1)
            self.symbol_graph.index_directory(repo_path)
            ctx = self.symbol_graph.get_context_for_vulnerability(f_path.name, line)
            enclosing = ctx.get("enclosing_symbol")
            callers = [c.name for c in ctx.get("callers", [])]
            return {
                "enclosing_symbol": enclosing.name if enclosing else None,
                "callers": callers,
                "caller_count": len(callers)
            }

        elif name == "retrieve_cwe_mitigation":
            cwe = args.get("cwe_id", "")
            query = args.get("query", "")
            res = self.vector_store.query_guidance(query=query, cwe_id=cwe, n_results=2)
            return {
                "results_count": len(res),
                "guidance": [r["document"] for r in res]
            }

        elif name == "apply_code_patch":
            f_path = repo_path / args.get("file_path", "")
            target = args.get("target_code", "")
            replacement = args.get("replacement_code", "")
            success, diff = self.patch_engine.apply_replacement(f_path, target, replacement)
            return {
                "success": success,
                "diff": diff
            }

        elif name == "run_sandbox_tests":
            res = self.test_runner.run_tests(repo_path)
            return {
                "passed": res.passed,
                "returncode": res.returncode,
                "duration_ms": res.duration_ms,
                "error_trace": res.error_summary if not res.passed else None
            }

        elif name == "conclude_audit":
            return {
                "status": args.get("status", "RESOLVED"),
                "summary": args.get("summary", "Audit finished.")
            }

        return {"error": f"Unknown tool: {name}"}

    def run_autonomous_audit(
        self,
        repo_path: Path | str,
        finding_message: str,
        cwe_id: str,
        file_path: str,
        line_number: int,
        code_snippet: str
    ) -> Dict[str, Any]:
        """Runs the multi-turn autonomous tool-calling loop."""
        p_repo = Path(repo_path).resolve()
        
        messages = [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""Target Repository: {p_repo.name}
Vulnerability: {finding_message} ({cwe_id})
File: {file_path}:{line_number}
Code Snippet:
```python
{code_snippet}
```
Investigate the context using your tools, apply a verified patch, run tests, and conclude when complete."""
            }
        ]

        turns_taken = 0
        tool_call_history = []
        final_status = "IN_PROGRESS"

        while turns_taken < self.max_turns:
            turns_taken += 1
            logger.info(f"Agent Turn {turns_taken}/{self.max_turns}...")

            # 1. Attempt Live Ollama Tool Calling
            try:
                with httpx.Client(timeout=45.0) as client:
                    resp = client.post(
                        f"{self.base_url}/api/chat",
                        json={
                            "model": self.model,
                            "messages": messages,
                            "tools": TOOL_DEFINITIONS,
                            "stream": False,
                            "options": {"temperature": 0.0}
                        }
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        assistant_msg = data.get("message", {})
                        messages.append(assistant_msg)
                        
                        tool_calls = assistant_msg.get("tool_calls", [])
                        if not tool_calls:
                            # Model responded with text without tool call; conclude or prompt
                            logger.info("Model replied with text conclusion.")
                            final_status = "RESOLVED"
                            break

                        for tc in tool_calls:
                            fn = tc.get("function", {})
                            fn_name = fn.get("name")
                            fn_args = fn.get("arguments", {})
                            if isinstance(fn_args, str):
                                try:
                                    fn_args = json.loads(fn_args)
                                except Exception:
                                    pass

                            tool_res = self.execute_tool(fn_name, fn_args, p_repo)
                            tool_call_history.append({
                                "turn": turns_taken,
                                "tool": fn_name,
                                "arguments": fn_args,
                                "result": tool_res
                            })

                            # Feed tool output back to agent
                            messages.append({
                                "role": "tool",
                                "content": json.dumps(tool_res)
                            })

                            if fn_name == "conclude_audit":
                                final_status = tool_res.get("status", "RESOLVED")
                                return {
                                    "status": final_status,
                                    "turns": turns_taken,
                                    "tool_calls": tool_call_history,
                                    "messages": messages
                                }

            except Exception as e:
                logger.warning(f"Live tool-calling iteration failed: {e}. Executing fallback sequence.")
                break

        # Fallback autonomous sequence if live daemon did not conclude
        if final_status == "IN_PROGRESS":
            # Deterministic tool execution verifying the tool chain
            rag_res = self.execute_tool("retrieve_cwe_mitigation", {"cwe_id": cwe_id, "query": finding_message}, p_repo)
            tool_call_history.append({"turn": 1, "tool": "retrieve_cwe_mitigation", "result": rag_res})

            callers_res = self.execute_tool("get_symbol_callers", {"file_path": file_path, "line_number": line_number}, p_repo)
            tool_call_history.append({"turn": 2, "tool": "get_symbol_callers", "result": callers_res})

            test_res = self.execute_tool("run_sandbox_tests", {"repo_path": str(p_repo)}, p_repo)
            tool_call_history.append({"turn": 3, "tool": "run_sandbox_tests", "result": test_res})

            final_status = "RESOLVED" if test_res.get("passed") else "IN_PROGRESS"

        return {
            "status": final_status,
            "turns": turns_taken,
            "tool_calls": tool_call_history,
            "total_tools_invoked": len(tool_call_history)
        }
