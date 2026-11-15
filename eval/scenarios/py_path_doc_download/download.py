"""Document storage retrieval module."""
import os
from pathlib import Path

STORAGE_ROOT = Path(__file__).resolve().parent / "docs"

def init_docs():
    STORAGE_ROOT.mkdir(exist_ok=True)
    (STORAGE_ROOT / "invoice.pdf").write_text("INVOICE_CONTENT", encoding="utf-8")

def get_document(filename: str) -> str:
    # VULNERABILITY: Path Traversal via unvalidated path join (AST Security / CWE-22)
    file_path = os.path.join(str(STORAGE_ROOT), filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

