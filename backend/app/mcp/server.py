"""Model Context Protocol (MCP) Server for SentinelAI.

Exposes codebase AST indexing, static security scanning, sandbox test execution,
patch diffing, and ChromaDB Vector RAG retrieval as standardized MCP tools.
Compatible with MCP 2.x specification (Claude Desktop, Cursor, and agent clients).
"""
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from mcp.server.mcpserver import MCPServer

from app.ast_engine.symbol_graph import SymbolGraph
from app.scanners.bandit_runner import BanditScanner
from app.sandbox.runner import TestRunner
from app.sandbox.patch_engine import PatchEngine
from app.rag.vector_store import CWEVectorStore

logger = logging.getLogger(__name__)

# Initialize Core Services for MCP Server
server = MCPServer(
    name="SentinelAI-MCP",
    version="1.0.0",
    description="SentinelAI Autonomous Security & AST Refactoring MCP Server"
)

symbol_graph = SymbolGraph()
bandit_scanner = BanditScanner()
test_runner = TestRunner()
patch_engine = PatchEngine()
vector_store = CWEVectorStore()


@server.tool(
    name="scan_repository",
    description="Scans a repository using Bandit and Tree-sitter AST rules to detect security vulnerabilities (CWE-89, CWE-78, CWE-22, etc.)."
)
def scan_repository(repo_path: str) -> Dict[str, Any]:
    """Scans target repository and returns structured vulnerability findings."""
    p = Path(repo_path).resolve()
    if not p.exists():
        return {"error": f"Repository path not found: {repo_path}", "findings": []}

    report = bandit_scanner.scan_directory(p)
    findings_list = [
        {
            "id": f.id,
            "cwe_id": f.cwe_id,
            "check_id": f.check_id,
            "message": f.message,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "code_snippet": f.code_snippet,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        }
        for f in report.findings
    ]
    return {
        "repo_path": str(p),
        "total_findings": len(findings_list),
        "findings": findings_list,
    }


@server.tool(
    name="get_symbol_callers",
    description="Resolves the enclosing function/method and cross-file caller dependencies for a vulnerability using Tree-sitter CST call graphs."
)
def get_symbol_callers(file_path: str, line_number: int) -> Dict[str, Any]:
    """Retrieves enclosing symbol and callers across the codebase for the specified line."""
    p = Path(file_path).resolve()
    if not p.exists():
        return {"error": f"File not found: {file_path}"}

    # Index the parent repository if not already indexed
    repo_root = p.parent
    symbol_graph.index_directory(repo_root)

    ctx = symbol_graph.get_context_for_vulnerability(p.name, line_number)
    enclosing = ctx.get("enclosing_symbol")
    callers = [c.name for c in ctx.get("callers", [])]

    return {
        "file_path": str(p),
        "line_number": line_number,
        "enclosing_symbol": enclosing.name if enclosing else None,
        "enclosing_type": enclosing.type if enclosing else None,
        "callers": callers,
        "caller_count": len(callers),
    }


@server.tool(
    name="retrieve_cwe_mitigation",
    description="Performs semantic vector search (ChromaDB) for CWE mitigation guidelines and secure refactoring patterns."
)
def retrieve_cwe_mitigation(cwe_id: str, query: str, top_k: int = 2) -> Dict[str, Any]:
    """Queries ChromaDB vector store for relevant CWE security patterns and examples."""
    results = vector_store.query_guidance(query=query, cwe_id=cwe_id, n_results=top_k)
    return {
        "cwe_id": cwe_id,
        "query": query,
        "results_count": len(results),
        "guidance": results,
        "formatted_prompt": vector_store.format_guidance_for_prompt(results),
    }


@server.tool(
    name="apply_code_patch",
    description="Applies a replacement code patch to a file with generic stdlib import resolution, diff generation, and automatic rollback backup."
)
def apply_code_patch(file_path: str, target_code: str, replacement_code: str) -> Dict[str, Any]:
    """Applies patch to target file and returns a unified git diff."""
    p = Path(file_path).resolve()
    success, diff = patch_engine.apply_replacement(p, target_code, replacement_code)
    return {
        "file_path": str(p),
        "success": success,
        "diff": diff,
    }


@server.tool(
    name="rollback_patch",
    description="Rolls back a previously patched file to its original pristine state."
)
def rollback_patch(file_path: str) -> Dict[str, Any]:
    """Restores the target file from backup store."""
    p = Path(file_path).resolve()
    restored = patch_engine.rollback_file(p)
    return {
        "file_path": str(p),
        "restored": restored,
    }


@server.tool(
    name="run_sandbox_tests",
    description="Executes unit tests in an isolated, timeout-enforced, environment-scrubbed subprocess sandbox. Returns pass/fail status and error traces."
)
def run_sandbox_tests(repo_path: str, timeout_seconds: int = 15) -> Dict[str, Any]:
    """Runs repository test suite inside containment sandbox."""
    p = Path(repo_path).resolve()
    if not p.exists():
        return {"error": f"Repository not found: {repo_path}", "passed": False}

    runner = TestRunner(timeout_seconds=timeout_seconds)
    result = runner.run_tests(p)
    return {
        "repo_path": str(p),
        "passed": result.passed,
        "returncode": result.returncode,
        "duration_ms": result.duration_ms,
        "error_trace": result.error_summary if not result.passed else None,
    }


@server.resource(
    uri="cwe://catalog",
    name="CWE Security Catalog",
    description="Listing of all 9 supported CWE vulnerability classes with descriptions."
)
def get_cwe_catalog() -> str:
    from app.rag.knowledge_base import CWE_KNOWLEDGE_DOCS
    catalog = ["# SentinelAI Supported CWE Catalog\n"]
    for doc in CWE_KNOWLEDGE_DOCS:
        catalog.append(f"- **{doc['metadata']['cwe_id']}**: {doc['title']} ({doc['metadata']['category']})")
    return "\n".join(catalog)


def run_cli():
    """CLI entry point for running the MCP server over stdio."""
    import sys
    print("Starting SentinelAI MCP Server on stdio transport...", file=sys.stderr)
    server.run(transport="stdio")


if __name__ == "__main__":
    run_cli()
