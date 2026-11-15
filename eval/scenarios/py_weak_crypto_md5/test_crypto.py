"""Unit tests verifying cryptographic algorithm compliance."""
from hasher import hash_password
from user import create_user_record

def test_hash_strength_compliance():
    digest = hash_password("Password123!")
    # MD5 produces 32-character hex; SHA-256 produces 64-character hex
    assert len(digest) >= 64, "Security violation: Hash length indicates weak MD5 (< 64 hex characters)!"
    assert digest != "86fb269d190d2c85f6e0468ceca42a20", "MD5 digest detected!"

def test_user_creation_integration():
    record = create_user_record("alice", "MySecret")
    assert record["user"] == "alice"
    assert len(record["hash"]) >= 64

