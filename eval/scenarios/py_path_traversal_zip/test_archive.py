"""Unit tests for archive extraction and Zip Slip containment."""
import io
import zipfile
import pytest
from pathlib import Path
from archive import extract_archive
from extractor import unpack_package

def create_mock_zip(files_dict):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for name, content in files_dict.items():
            z.writestr(name, content)
    bio.seek(0)
    return bio

def test_valid_unpacking(tmp_path):
    zip_data = create_mock_zip({"doc.txt": "sample data", "sub/info.txt": "sub info"})
    zip_file = tmp_path / "valid.zip"
    zip_file.write_bytes(zip_data.read())

    dest = tmp_path / "output"
    dest.mkdir()
    names = unpack_package(str(zip_file), str(dest))
    assert "doc.txt" in names

def test_zip_slip_defense(tmp_path):
    # Malicious archive member attempting directory escape
    zip_data = create_mock_zip({"../../malicious.txt": "HACKED"})
    zip_file = tmp_path / "malicious.zip"
    zip_file.write_bytes(zip_data.read())

    dest = tmp_path / "output_safe"
    dest.mkdir()
    with pytest.raises((PermissionError, ValueError)):
        extract_archive(str(zip_file), str(dest))

