"""High-level archive package unpacker."""
from pathlib import Path
from typing import List
from archive import extract_archive

def unpack_package(archive_file: str, destination: str) -> List[str]:
    extract_archive(archive_file, destination)
    dest_path = Path(destination)
    return [p.name for p in dest_path.iterdir()]

