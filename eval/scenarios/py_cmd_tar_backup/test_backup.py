from service import trigger_backup

def test_backup_execution():
    res = trigger_backup("documents")
    assert res["status"] == 0
    assert "BACKUP_documents" in res["stdout"]

