"""LangGraph state machine for autonomous security refactoring and verification."""
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any

from langgraph.graph import StateGraph, END
from app.agent.state import AgentState
from app.agent.model_client import LocalModelClient
from app.ast_engine.symbol_graph import SymbolGraph
from app.scanners.bandit_runner import BanditScanner
from app.scanners.schemas import FindingStatus
from app.sandbox.patch_engine import PatchEngine
from app.sandbox.runner import TestRunner

logger = logging.getLogger(__name__)

class SentinelAgent:
    """Orchestrates the autonomous security audit and self-healing refactoring loop."""

    def __init__(self, bandit_exec: str = None, pytest_exec: str = None):
        self.scanner = BanditScanner(bandit_executable=bandit_exec)
        self.symbol_graph = SymbolGraph()
        self.patch_engine = PatchEngine()
        self.test_runner = TestRunner(pytest_executable=pytest_exec)
        self.model_client = LocalModelClient()
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        workflow.add_node("scan_and_index", self.node_scan_and_index)
        workflow.add_node("select_finding", self.node_select_finding)
        workflow.add_node("plan_and_patch", self.node_plan_and_patch)
        workflow.add_node("verify_in_sandbox", self.node_verify_in_sandbox)

        workflow.set_entry_point("scan_and_index")

        workflow.add_edge("scan_and_index", "select_finding")
        
        workflow.add_conditional_edges(
            "select_finding",
            self.route_after_select,
            {
                "continue": "plan_and_patch",
                "done": END,
            },
        )

        workflow.add_edge("plan_and_patch", "verify_in_sandbox")

        workflow.add_conditional_edges(
            "verify_in_sandbox",
            self.route_after_verify,
            {
                "retry": "plan_and_patch",
                "next": "select_finding",
            },
        )

        return workflow.compile()

    def node_scan_and_index(self, state: AgentState) -> Dict[str, Any]:
        repo_path = Path(state.repository_path).resolve()
        state.add_log(f"🔍 Ingesting codebase and parsing AST: {repo_path.name}")
        
        # AST Symbol Indexing
        indexed_files = self.symbol_graph.index_directory(repo_path)
        state.add_log(f"🌲 Tree-sitter indexed {indexed_files} source files into symbol call graph.")

        # Static Vulnerability Scanning
        report = self.scanner.scan_directory(repo_path)
        state.findings = report.findings
        state.add_log(f"🛡️ Security scan complete: found {len(report.findings)} actionable vulnerabilities.")
        state.status = "SCAN_COMPLETE"

        return {"findings": state.findings, "status": state.status, "logs": state.logs}

    def node_select_finding(self, state: AgentState) -> Dict[str, Any]:
        if state.current_finding_index >= len(state.findings):
            state.add_log("🎉 All security findings processed! Audit complete.")
            state.status = "COMPLETED"
            return {"status": state.status, "logs": state.logs}

        finding = state.findings[state.current_finding_index]
        state.iteration = 0
        state.last_test_error = None
        state.add_log(f"🎯 Targeted Finding [{finding.id}]: {finding.message} in {finding.file_path}:{finding.line_start}")
        state.status = "PLANNING"
        return {"current_finding_index": state.current_finding_index, "iteration": 0, "status": state.status, "logs": state.logs}

    def route_after_select(self, state: AgentState) -> str:
        if state.current_finding_index >= len(state.findings):
            return "done"
        return "continue"

    def node_plan_and_patch(self, state: AgentState) -> Dict[str, Any]:
        finding = state.findings[state.current_finding_index]
        repo_path = Path(state.repository_path).resolve()
        target_file = repo_path / finding.file_path

        state.add_log(f"🧠 Context retrieval: resolving callers for {finding.file_path}:{finding.line_start}")
        ctx = self.symbol_graph.get_context_for_vulnerability(finding.file_path, finding.line_start)
        enclosing = ctx.get("enclosing_symbol")
        callers = [c.name for c in ctx.get("callers", [])]

        state.add_log(f"✍️ Synthesizing patch (Attempt {state.iteration + 1}/{state.max_iterations})...")
        
        patch_data = self.model_client.generate_patch(
            vulnerability_message=finding.message,
            cwe_id=finding.cwe_id,
            code_snippet=finding.code_snippet,
            enclosing_symbol_name=enclosing.name if enclosing else None,
            callers=callers,
            test_failure_trace=state.last_test_error,
        )

        target_code = patch_data.get("target_code", "")
        replacement_code = patch_data.get("replacement_code", "")

        success, diff = self.patch_engine.apply_replacement(target_file, target_code, replacement_code)

        if success:
            finding.suggested_fix_diff = diff
            state.applied_diffs.append(diff)
            state.add_log(f"✨ Applied patch to {finding.file_path}. Unified diff generated.")
        else:
            state.add_log(f"⚠️ Failed to apply replacement to {finding.file_path}: {diff}")

        state.status = "TESTING"
        return {
            "applied_diffs": state.applied_diffs,
            "status": state.status,
            "logs": state.logs,
        }

    def node_verify_in_sandbox(self, state: AgentState) -> Dict[str, Any]:
        repo_path = Path(state.repository_path).resolve()
        finding = state.findings[state.current_finding_index]
        state.add_log("🧪 Executing test suite in sandbox verification runner...")

        result = self.test_runner.run_tests(repo_path)
        finding.test_stdout = result.stdout

        if result.passed:
            state.add_log(f"✅ Sandbox verification PASSED in {result.duration_ms}ms! Zero regressions.")
            finding.status = FindingStatus.RESOLVED
            finding.iterations_taken = state.iteration + 1
            state.current_finding_index += 1
            state.last_test_error = None
        else:
            state.iteration += 1
            state.last_test_error = result.error_summary
            state.add_log(f"❌ Tests FAILED: {result.error_summary}")

            if state.iteration >= state.max_iterations:
                state.add_log(f"🛑 Max self-healing iterations reached for [{finding.id}]. Rolling back.")
                self.patch_engine.rollback_file(repo_path / finding.file_path)
                finding.status = FindingStatus.FAILED
                state.current_finding_index += 1

        return {
            "findings": state.findings,
            "current_finding_index": state.current_finding_index,
            "iteration": state.iteration,
            "last_test_error": state.last_test_error,
            "logs": state.logs,
        }

    def route_after_verify(self, state: AgentState) -> str:
        # If the finding was marked resolved or failed, current_finding_index was incremented
        if state.last_test_error and state.iteration < state.max_iterations:
            return "retry"
        return "next"
