"""API layer exposing file retrieval endpoint."""
from file_service import read_user_file

def get_report_content(report_name: str) -> str:
    """Retrieves report contents by delegating to file_service."""
    return read_user_file(report_name)

