"""Database client service layer."""
from credentials import get_connection_string

def connect_db_client() -> str:
    return get_connection_string()

