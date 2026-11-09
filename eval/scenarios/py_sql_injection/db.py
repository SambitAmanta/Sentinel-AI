"""Database access layer with vulnerable raw SQL query."""
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
