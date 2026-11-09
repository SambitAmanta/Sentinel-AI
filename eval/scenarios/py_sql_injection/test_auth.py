"""Regression and security test suite for authentication scenario."""
import pytest
from db import init_db, get_user_by_id
from service import authenticate_and_get_profile

@pytest.fixture
def db_conn():
    conn = init_db()
    yield conn
    conn.close()

def test_valid_user_fetch(db_conn):
    user = get_user_by_id(db_conn, "usr_1")
    assert user is not None
    assert user["username"] == "alice"
    assert user["role"] == "admin"

def test_user_profile_service(db_conn):
    profile = authenticate_and_get_profile(db_conn, "usr_2")
    assert profile is not None
    assert profile["username"] == "bob"
    assert profile["status"] == "ACTIVE"

def test_sql_injection_defense(db_conn):
    # An injection attempt searching for a non-existent ID with SQL payload
    payload = "nonexistent' OR '1'='1"
    user = get_user_by_id(db_conn, payload)
    # With parameterized queries, no user matches this string literal ID
    assert user is None, "SQL Injection payload succeeded in retrieving user!"

