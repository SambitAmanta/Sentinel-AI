"""API route handler calling product repository."""
import sqlite3
from typing import List, Dict, Any
from repo import search_products

def handle_search_request(conn: sqlite3.Connection, query: str, limit: int = 10) -> List[Dict[str, Any]]:
    return search_products(conn, query, limit=limit)

