"""Regression test suite for file storage service."""
import pytest
from pathlib import Path
from file_service import init_storage, read_user_file
from api import get_report_content

@pytest.fixture(autouse=True)
def setup_storage(tmp_path, monkeypatch):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)
    (storage_dir / "welcome.txt").write_text("Hello World", encoding="utf-8")
    
    # Secret outside storage
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("SUPER_SECRET_TOKEN", encoding="utf-8")

    import file_service
    monkeypatch.setattr(file_service, "BASE_STORAGE", storage_dir)

def test_valid_file_read():
    content = read_user_file("welcome.txt")
    assert content == "Hello World"

def test_api_report_endpoint():
    content = get_report_content("welcome.txt")
    assert "Hello" in content

def test_path_traversal_defense():
    # Attempting to escape storage directory with traversal
    with pytest.raises((PermissionError, ValueError)):
        read_user_file("../secret.txt")

