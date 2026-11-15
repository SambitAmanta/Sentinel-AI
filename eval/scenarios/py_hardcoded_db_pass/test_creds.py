from service import connect_db_client

def test_database_connection_string():
    conn_str = connect_db_client()
    assert conn_str.startswith("postgresql://admin:")
    assert "db.production:5432/app" in conn_str

