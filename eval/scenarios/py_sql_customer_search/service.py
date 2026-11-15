"""Customer service layer."""
import sqlite3
from typing import List, Dict, Any
from db import search_customers

def get_customer_by_name(conn: sqlite3.Connection, name: str) -> List[Dict[str, Any]]:
    return search_customers(conn, name)

