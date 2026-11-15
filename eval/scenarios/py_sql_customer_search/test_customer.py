from db import init_customer_db
from service import get_customer_by_name

def test_valid_customer_lookup():
    conn = init_customer_db()
    res = get_customer_by_name(conn, "Acme Corp")
    assert len(res) == 1
    assert res[0]["name"] == "Acme Corp"

