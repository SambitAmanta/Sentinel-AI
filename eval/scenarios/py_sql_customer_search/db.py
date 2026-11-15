"""Customer database access module."""
import sqlite3
from typing import List, Dict, Any

def init_customer_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE customers (id INT PRIMARY KEY, name TEXT, email TEXT)")
    cur.execute("INSERT INTO customers VALUES (1, 'Acme Corp', 'contact@acme.com')")
    cur.execute("INSERT INTO customers VALUES (2, 'Globex Inc', 'info@globex.com')")
    conn.commit()
    return conn

def search_customers(conn: sqlite3.Connection, query: str) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    # VULNERABILITY: Raw SQL query string formatting (Bandit B608 / CWE-89)
    sql = f"SELECT id, name, email FROM customers WHERE name = '{query}'"
    cur.execute(sql)
    rows = cur.fetchall()
    return [{"id": r[0], "name": r[1], "email": r[2]} for r in rows]

