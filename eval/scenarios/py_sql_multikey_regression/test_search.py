"""Unit test suite checking SQL injection defense and pagination contract."""
import pytest
from repo import init_product_db, search_products
from routes import handle_search_request

@pytest.fixture
def db():
    conn = init_product_db()
    yield conn
    conn.close()

def test_sql_injection_defense(db):
    payload = "' OR '1'='1"
    results = search_products(db, payload)
    # Parameterized query should treat the payload as literal string, returning 0 matches
    assert len(results) == 0, "SQL injection succeeded in dumping table!"

def test_pagination_contract(db):
    # Regression test: query matches 3 laptops, but limit=2 must be strictly respected
    results = handle_search_request(db, "Laptop", limit=2)
    assert len(results) == 2, f"Expected 2 paginated items, got {len(results)}"

