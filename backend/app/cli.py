"""Command Line Interface for running SentinelAI audits directly in the terminal."""
import argparse
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_root = str(Path(__file__).resolve().parent.parent)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from app.agent.graph import SentinelAgent
from app.agent.state import AgentState
from app.scanners.schemas import FindingStatus

console = Console()

def main():
    parser = argparse.ArgumentParser(description="SentinelAI: Autonomous Codebase Security Audit & Refactoring Agent")
    parser.add_argument(
        "--repo",
        type=str,
        default="eval/scenarios/py_sql_injection",
        help="Path to the repository or directory to audit and refactor.",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        console.print(f"[red]Error: Target repository path does not exist: {repo_path}[/red]")
        sys.exit(1)

    console.print(Panel(f"[bold cyan]SentinelAI Engine[/bold cyan]\nTarget: [yellow]{repo_path}[/yellow]", title="🚀 Initializing Audit"))

    agent = SentinelAgent()
    state = AgentState(repository_path=str(repo_path))

    with console.status("[bold green]Executing autonomous AST analysis & vulnerability triage...[/bold green]"):
        final_state = agent.graph.invoke(state)

    # Print logs
    console.print("\n[bold]Execution Log Stream:[/bold]")
    for log_msg in final_state.get("logs", []):
        console.print(f"  {log_msg}")

    # Summary Table
    findings = final_state.get("findings", [])
    table = Table(title="Security Audit & Remediation Report")
    table.add_column("ID", style="cyan")
    table.add_column("Rule / CWE", style="magenta")
    table.add_column("File:Line", style="white")
    table.add_column("Severity", style="bold red")
    table.add_column("Status", style="bold green")

    for f in findings:
        status_style = "green" if f.status == FindingStatus.RESOLVED else "red"
        table.add_row(
            f.id,
            f"{f.check_id} ({f.cwe_id or 'N/A'})",
            f"{f.file_path}:{f.line_start}",
            f.severity.value,
            f"[{status_style}]{f.status.value}[/{status_style}]",
        )

    console.print("\n", table)

    # Output Diffs
    diffs = final_state.get("applied_diffs", [])
    if diffs:
        console.print("\n[bold green]Applied Unified Git Diffs:[/bold green]")
        for diff in diffs:
            syntax = Syntax(diff, "diff", theme="monokai", line_numbers=False)
            console.print(syntax)

if __name__ == "__main__":
    main()
