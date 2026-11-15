"""Product repository with vulnerable dynamic SQL search query."""
import sqlite3
from typing import List, Dict, Any

def init_product_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE products (id INT PRIMARY KEY, name TEXT, price REAL)")
    items = [
        (1, "Laptop Pro", 1200.0),
        (2, "Laptop Air", 999.0),
        (3, "Laptop Sleeve", 29.0),
        (4, "Phone Stand", 15.0),
        (5, "Desk Lamp", 45.0),
        (6, "USB Cable", 9.0),
    ]
    cursor.executemany("INSERT INTO products VALUES (?, ?, ?)", items)
    conn.commit()
    return conn

def search_products(conn: sqlite3.Connection, query_term: str, limit: int = 10) -> List[Dict[str, Any]]:
    cursor = conn.cursor()
    # VULNERABILITY: Bandit B608 / CWE-89 raw string concatenation
    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{query_term}%' LIMIT {limit}"
    cursor.execute(sql)
    return [{"id": r[0], "name": r[1], "price": r[2]} for r in cursor.fetchall()]

