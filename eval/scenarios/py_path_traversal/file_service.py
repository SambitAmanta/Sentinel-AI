"""Document storage service with path traversal vulnerability."""
import os
from pathlib import Path

BASE_STORAGE = Path(__file__).resolve().parent / "storage"

def init_storage():
    BASE_STORAGE.mkdir(parents=True, exist_ok=True)
    (BASE_STORAGE / "welcome.txt").write_text("Hello World", encoding="utf-8")

def read_user_file(filename: str) -> str:
    # VULNERABILITY: Path traversal via unvalidated path joining (CWE-22 / Bandit B108)
    file_path = os.path.join(str(BASE_STORAGE), filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()
