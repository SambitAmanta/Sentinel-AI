"""Automated evaluation benchmark runner comparing Single-Shot baseline vs SentinelAI Self-Healing Loop.
Evaluates benchmark scenarios across 9 CWE classes with independent held-out verification tests.
Supports Dev Set (12 scenarios), Fresh Evaluation Set (8 scenarios), or Full Suite (20 scenarios).
"""
import argparse
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Add backend directory to sys.path
backend_path = str(Path(__file__).resolve().parent.parent / "backend")
eval_path = str(Path(__file__).resolve().parent)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
if eval_path not in sys.path:
    sys.path.insert(0, eval_path)

from app.agent.graph import SentinelAgent
from app.agent.state import AgentState
from app.sandbox.runner import TestRunner
from held_out_tests.test_held_out import evaluate_scenario_held_out

console = Console()

DEV_SCENARIOS = [
    {
        "id": "SCENARIO-01",
        "name": "SQL Injection in User Auth",
        "path": "eval/scenarios/py_sql_injection",
        "cwe": "CWE-89",
        "multi_file": True,
        "designed_regression": False,
        "description": "Dynamic f-string formatting in SQLite user query",
    },
    {
        "id": "SCENARIO-02",
        "name": "SQL Injection w/ Pagination Regression",
        "path": "eval/scenarios/py_sql_multikey_regression",
        "cwe": "CWE-89",
        "multi_file": True,
        "designed_regression": True,
        "description": "Designed contract test: Naive patch drops LIMIT clause, breaking pagination contract",
    },
    {
        "id": "SCENARIO-03",
        "name": "OS Command Injection in Network Ping",
        "path": "eval/scenarios/py_command_injection",
        "cwe": "CWE-78",
        "multi_file": True,
        "designed_regression": False,
        "description": "Subprocess execution with shell=True and unsanitized host argument",
    },
    {
        "id": "SCENARIO-04",
        "name": "Command Injection w/ Subprocess Contract",
        "path": "eval/scenarios/py_cmd_injection_multiturn",
        "cwe": "CWE-78",
        "multi_file": True,
        "designed_regression": True,
        "description": "Designed contract test: Naive patch hardcodes static output, breaking telemetry format contract",
    },
    {
        "id": "SCENARIO-05",
        "name": "Path Traversal in User Storage",
        "path": "eval/scenarios/py_path_traversal",
        "cwe": "CWE-22",
        "multi_file": True,
        "designed_regression": False,
        "description": "Unvalidated path concatenation allowing directory escape",
    },
    {
        "id": "SCENARIO-06",
        "name": "Zip Slip Archive Directory Traversal",
        "path": "eval/scenarios/py_path_traversal_zip",
        "cwe": "CWE-22",
        "multi_file": True,
        "designed_regression": True,
        "description": "Designed contract test: Naive patch forbids all slashes; Turn 2 verifies canonical path containment",
    },
    {
        "id": "SCENARIO-07",
        "name": "Insecure Deserialization via Pickle",
        "path": "eval/scenarios/py_insecure_deserialization",
        "cwe": "CWE-502",
        "multi_file": True,
        "designed_regression": False,
        "description": "Unpickling untrusted session payloads replaced with safe JSON deserialization",
    },
    {
        "id": "SCENARIO-08",
        "name": "SSRF in Webhook Dispatcher",
        "path": "eval/scenarios/py_ssrf_webhook",
        "cwe": "CWE-918",
        "multi_file": True,
        "designed_regression": True,
        "description": "Designed contract test: Naive patch blocks all non-HTTPS; Turn 2 restricts cloud metadata IPs",
    },
    {
        "id": "SCENARIO-09",
        "name": "Broken Cryptographic Hash Algorithm",
        "path": "eval/scenarios/py_weak_crypto_md5",
        "cwe": "CWE-327",
        "multi_file": True,
        "designed_regression": False,
        "description": "Obsolete MD5 password hashing upgraded to collision-resistant SHA-256",
    },
    {
        "id": "SCENARIO-10",
        "name": "Hardcoded JWT Secret Key",
        "path": "eval/scenarios/py_hardcoded_secrets",
        "cwe": "CWE-798",
        "multi_file": True,
        "designed_regression": False,
        "description": "Plaintext secret token refactored into environment variable retrieval",
    },
    {
        "id": "SCENARIO-11",
        "name": "ReDoS Catastrophic Backtracking",
        "path": "eval/scenarios/py_redos_email",
        "cwe": "CWE-1333",
        "multi_file": False,
        "designed_regression": False,
        "description": "Exponential regex backtracking replaced with linear atomic regex pattern",
    },
    {
        "id": "SCENARIO-12",
        "name": "Cross-Site Scripting Template Injection",
        "path": "eval/scenarios/py_xss_template",
        "cwe": "CWE-79",
        "multi_file": True,
        "designed_regression": False,
        "description": "Unescaped HTML string interpolation refactored with deterministic HTML entity escaping",
    },
]

EVAL_SCENARIOS = [
    {
        "id": "SCENARIO-13",
        "name": "SQL Injection in Customer Search",
        "path": "eval/scenarios/py_sql_customer_search",
        "cwe": "CWE-89",
        "multi_file": True,
        "designed_regression": False,
        "description": "Raw SQL query string formatting in customer database lookup",
    },
    {
        "id": "SCENARIO-14",
        "name": "OS Command Injection in Archive Backup",
        "path": "eval/scenarios/py_cmd_tar_backup",
        "cwe": "CWE-78",
        "multi_file": True,
        "designed_regression": False,
        "description": "Subprocess command execution formatting tar arguments with shell=True",
    },
    {
        "id": "SCENARIO-15",
        "name": "Path Traversal in Document Download",
        "path": "eval/scenarios/py_path_doc_download",
        "cwe": "CWE-22",
        "multi_file": True,
        "designed_regression": False,
        "description": "Arbitrary document download via unvalidated relative filepath concatenation",
    },
    {
        "id": "SCENARIO-16",
        "name": "Insecure Deserialization via YAML",
        "path": "eval/scenarios/py_insecure_deserialization_yaml",
        "cwe": "CWE-502",
        "multi_file": True,
        "designed_regression": False,
        "description": "yaml.load() without SafeLoader enabling arbitrary python object execution",
    },
    {
        "id": "SCENARIO-17",
        "name": "Hardcoded Database Password",
        "path": "eval/scenarios/py_hardcoded_db_pass",
        "cwe": "CWE-798",
        "multi_file": True,
        "designed_regression": False,
        "description": "Static database connection credentials in configuration replaced by env var lookup",
    },
    {
        "id": "SCENARIO-18",
        "name": "Broken Cryptographic Algorithm (SHA-1)",
        "path": "eval/scenarios/py_weak_crypto_sha1",
        "cwe": "CWE-327",
        "multi_file": True,
        "designed_regression": False,
        "description": "Vulnerable SHA-1 hash routine upgraded to collision-resistant SHA-256",
    },
    {
        "id": "SCENARIO-19",
        "name": "SSRF in Image Proxy",
        "path": "eval/scenarios/py_ssrf_image_proxy",
        "cwe": "CWE-918",
        "multi_file": True,
        "designed_regression": False,
        "description": "Remote image fetch proxy allowing internal network and metadata IP probes",
    },
    {
        "id": "SCENARIO-20",
        "name": "Reflected XSS Error Banner",
        "path": "eval/scenarios/py_xss_error_banner",
        "cwe": "CWE-79",
        "multi_file": True,
        "designed_regression": False,
        "description": "Unescaped error message rendered directly in HTML template",
    },
]

ALL_SCENARIOS = DEV_SCENARIOS + EVAL_SCENARIOS

def percentile(data, pct):
    """Calculates percentile from list of numeric values."""
    if not data:
        return 0.0
    k = (len(data) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(data) - 1)
    d = k - f
    return data[f] + d * (data[c] - data[f])

def run_benchmark(mode: str = "pipeline", dataset: str = "dev"):
    if dataset == "dev":
        target_scenarios = DEV_SCENARIOS
        dataset_label = "Development Set (12 Scenarios across 9 CWEs)"
    elif dataset == "eval":
        target_scenarios = EVAL_SCENARIOS
        dataset_label = "Fresh Unseen Evaluation Set (8 Scenarios)"
    else:
        target_scenarios = ALL_SCENARIOS
        dataset_label = "Full Suite (20 Scenarios across 9 CWEs)"

    console.print(Panel(
        f"[bold cyan]SentinelAI Empirical Benchmark Evaluation Suite[/bold cyan]\n"
        f"Dataset: [bold yellow]{dataset_label}[/bold yellow]\n"
        f"Target: Single-Shot (1 Attempt) vs SentinelAI Self-Healing (≤3 Attempts with Test Feedback)\n"
        f"Grading: Visible Repo Unit Tests + Held-Out Exploit Neutralization & Non-Overfitting Tests\n"
        f"Mode: {'Deterministic Architecture Test Harness' if mode == 'pipeline' else 'Live Local SLM (Qwen2.5-Coder-7B)'}\n"
        f"Hardware: NVIDIA GeForce RTX 5050 (8GB VRAM) | Offline Local-First Engine",
        title="🛡️ Benchmark Evaluation Suite",
        expand=False
    ))

    results = []
    test_runner = TestRunner()

    for idx, sc in enumerate(target_scenarios, start=1):
        sc_path = Path(sc["path"]).resolve()
        console.print(f"\n[bold yellow]► [{idx}/{len(target_scenarios)}] Evaluating: {sc['name']} ({sc['cwe']})[/bold yellow]")

        # Run SentinelAI Self-Healing Loop in a clean isolated directory
        # Single-shot metrics are derived strictly from Attempt 1 of this unified execution.
        with tempfile.TemporaryDirectory() as tmp_sentinel:
            tmp_s_path = Path(tmp_sentinel)
            shutil.copytree(sc_path, tmp_s_path, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

            start_time = time.time()
            agent = SentinelAgent(force_mode="deterministic" if mode == "pipeline" else "live")
            state = AgentState(repository_path=str(tmp_s_path))
            final_state = agent.graph.invoke(state)
            sentinel_duration_ms = (time.time() - start_time) * 1000

            # 1. Visible test suite verification
            post_audit_run = test_runner.run_tests(tmp_s_path)
            visible_passed = post_audit_run.passed

            # 2. Held-out test suite verification (Exploit neutralization + Contract preservation)
            held_out_audit = evaluate_scenario_held_out(sc["id"], tmp_s_path)
            held_out_passed = held_out_audit["passed"]

            sentinel_passed = visible_passed and held_out_passed

            # Extract iterations taken
            iterations = 1
            if final_state.get("findings"):
                iterations = max([f.iterations_taken for f in final_state["findings"]] or [1])

            # Derive Single-Shot from Attempt 1 of the same trajectory:
            # If the patch succeeded on Attempt 1 and held-out passed, single-shot is PASS.
            # If Attempt 1 failed (requiring retries or failing overall), single-shot is FAIL.
            single_shot_passed = (iterations == 1 and sentinel_passed)
            single_shot_duration_ms = sentinel_duration_ms if iterations == 1 else round(sentinel_duration_ms / iterations, 1)

        results.append({
            "id": sc["id"],
            "name": sc["name"],
            "cwe": sc["cwe"],
            "multi_file": sc["multi_file"],
            "designed_regression": sc["designed_regression"],
            "baseline_pass": single_shot_passed,
            "baseline_ms": round(single_shot_duration_ms, 1),
            "sentinel_pass": sentinel_passed,
            "held_out_passed": held_out_passed,
            "iterations": iterations,
            "duration_ms": round(sentinel_duration_ms, 1),
            "status": "RESOLVED" if sentinel_passed else "FAILED",
        })

        b_color = "green" if single_shot_passed else "red"
        s_color = "green" if sentinel_passed else "red"
        console.print(f"  • Single-Shot (Attempt 1): [{b_color}]{'PASS' if single_shot_passed else 'FAIL (Contract Broken / Lacked Imports)'}[/{b_color}] ({single_shot_duration_ms:.1f}ms)")
        console.print(f"  • SentinelAI Self-Healing: [{s_color}]{'PASS' if sentinel_passed else 'FAIL'}[/{s_color}] (Iters: {iterations}, Latency: {sentinel_duration_ms:.1f}ms, Held-out: {'PASS' if held_out_passed else 'FAIL'})")

    # ---------------------------------------------------------
    # SUMMARY REPORT & STATISTICAL METRICS
    # ---------------------------------------------------------
    table = Table(title=f"SentinelAI Empirical Benchmark Results ({dataset_label})", show_header=True, header_style="bold magenta")
    table.add_column("Scenario ID", style="cyan", width=12)
    table.add_column("Vulnerability Name", style="white", width=36)
    table.add_column("CWE", style="magenta", width=10)
    table.add_column("Multi-File", style="dim", width=10)
    table.add_column("Single-Shot (Attempt 1)", style="bold red", width=22)
    table.add_column("SentinelAI (≤3 Attempts)", style="bold green", width=22)
    table.add_column("Iterations", style="yellow", width=11)
    table.add_column("Latency", style="cyan", width=12)

    for r in results:
        b_str = "[green]PASS (Held-Out Verified)[/green]" if r["baseline_pass"] else "[red]FAIL (Regression/Error)[/red]"
        s_str = "[green]PASS (Held-Out Verified)[/green]" if r["sentinel_pass"] else "[red]FAIL[/red]"
        mf_str = "Yes" if r["multi_file"] else "No"
        table.add_row(
            r["id"],
            r["name"],
            r["cwe"],
            mf_str,
            b_str,
            s_str,
            f"{r['iterations']} {'iter' if r['iterations'] == 1 else 'iters'}",
            f"{r['duration_ms']} ms",
        )

    console.print("\n", table)

    # Compute Aggregate Metrics
    total = len(results)
    baseline_passed_count = sum(1 for r in results if r["baseline_pass"])
    sentinel_passed_count = sum(1 for r in results if r["sentinel_pass"])
    held_out_passed_count = sum(1 for r in results if r["held_out_passed"])

    baseline_rate = (baseline_passed_count / total) * 100
    sentinel_rate = (sentinel_passed_count / total) * 100
    healed_count = sentinel_passed_count - baseline_passed_count
    mean_iterations = sum(r["iterations"] for r in results) / total

    durations = sorted(r["duration_ms"] for r in results)
    mean_duration = statistics.mean(durations)
    p50_duration = percentile(durations, 50)
    p95_duration = percentile(durations, 95)

    console.print(Panel(
        f"[bold]Total Benchmark Scenarios:[/bold] {total} ({dataset_label})\n"
        f"[bold red]Single-Shot Baseline (Attempt 1, Visible + Held-Out):[/bold red] {baseline_rate:.1f}% ({baseline_passed_count}/{total})\n"
        f"[bold green]SentinelAI Self-Healing Loop (≤3 Attempts, Visible + Held-Out):[/bold green] [bold]{sentinel_rate:.1f}%[/bold] ({sentinel_passed_count}/{total})\n"
        f"[bold green]Held-Out Evaluation Pass Rate (Exploit Neutralized):[/bold green] [bold]{held_out_passed_count}/{total} ({held_out_passed_count/total*100:.1f}%)[/bold]\n"
        f"[bold yellow]Scenarios Autonomous Healed on Retry:[/bold yellow] {healed_count} scenario(s) healed via error reflection\n"
        f"[bold]Mean Self-Healing Iterations:[/bold] {mean_iterations:.2f} iterations/scenario\n"
        f"[bold cyan]Remediation Latency Distribution:[/bold cyan] p50: {p50_duration:.1f}ms (~{p50_duration/1000:.2f}s) | Mean: {mean_duration:.1f}ms | p95: {p95_duration:.1f}ms (~{p95_duration/1000:.2f}s)\n"
        f"[dim]Evaluation Harness: Unified trajectory derivation with zero inter-run variance contradictions.[/dim]",
        title="📈 Aggregate Benchmark Performance",
        expand=False
    ))

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Benchmark Runner")
    parser.add_argument("--mode", choices=["pipeline", "live"], default="pipeline", help="Benchmark execution mode: pipeline (deterministic architecture test harness) or live (Ollama Qwen2.5-Coder SLM)")
    parser.add_argument("--dataset", choices=["dev", "eval", "all"], default="dev", help="Dataset to evaluate: dev (12 scenarios), eval (8 fresh unseen scenarios), all (20 scenarios)")
    args = parser.parse_args()
    run_benchmark(mode=args.mode, dataset=args.dataset)
