"""Integration tests for SentinelAgent self-healing loop."""
import shutil
from pathlib import Path
from app.agent.graph import SentinelAgent
from app.agent.state import AgentState
from app.scanners.schemas import FindingStatus

def test_sentinel_agent_e2e_refactor(tmp_path):
    # Copy scenario to isolated tmp_path
    src_dir = Path("eval/scenarios/py_sql_injection")
    for f in src_dir.glob("*.py"):
        shutil.copy(f, tmp_path / f.name)

    # Set db.py to vulnerable state in tmp_path
    db_file = tmp_path / "db.py"
    db_file.write_text('''"""Database access layer with vulnerable raw SQL query."""
import sqlite3
from typing import Optional, Dict, Any

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    cursor.execute("INSERT INTO users VALUES ('usr_1', 'alice', 'admin')")
    cursor.execute("INSERT INTO users VALUES ('usr_2', 'bob', 'user')")
    conn.commit()
    return conn

def get_user_by_id(conn: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
    cursor = conn.cursor()
    # VULNERABILITY: Raw SQL query string formatting (Bandit B608 / CWE-89)
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None
''', encoding="utf-8")

    agent = SentinelAgent()
    state = AgentState(repository_path=str(tmp_path))
    final_state = agent.graph.invoke(state)

    assert final_state["status"] == "COMPLETED"
    assert len(final_state["findings"]) >= 1
    assert final_state["findings"][0].status == FindingStatus.RESOLVED

    # Check patched file in tmp_path has parameterized query
    patched_content = db_file.read_text(encoding="utf-8")
    assert "WHERE id = ?" in patched_content
