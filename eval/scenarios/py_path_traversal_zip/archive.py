"""Archive utility with Zip Slip path traversal vulnerability."""
import os
import zipfile
from pathlib import Path

def extract_archive(zip_path: str | Path, extract_to: str | Path) -> None:
    # VULNERABILITY: Zip Slip / CWE-22 arbitrary overwrite via unvalidated member paths
    dest = Path(extract_to).resolve()
    with zipfile.ZipFile(str(zip_path), "r") as z:
        for member in z.infolist():
            target_path = dest / member.filename
            # Vulnerable extraction without boundary check
            z.extract(member, str(dest))

