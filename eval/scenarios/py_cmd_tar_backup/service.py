"""Backup service layer."""
from backup import run_archive_backup

def trigger_backup(target_folder: str) -> dict:
    return run_archive_backup(target_folder)

