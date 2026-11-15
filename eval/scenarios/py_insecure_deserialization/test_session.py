"""Unit tests verifying safe serialization and pickle exploit defense."""
import json
import pickle
import pytest
from session import load_session_data
from auth import verify_user_session

class ExploitPayload:
    def __reduce__(self):
        return (eval, ("1 + 1",))

def test_safe_session_loading():
    # Safe json-encoded session payload
    valid_payload = json.dumps({"user_id": "usr_99", "role": "editor"}).encode("utf-8")
    data = load_session_data(valid_payload)
    assert data["user_id"] == "usr_99"

def test_auth_verification():
    valid_payload = json.dumps({"user_id": "alice"}).encode("utf-8")
    user_id = verify_user_session(valid_payload)
    assert user_id == "alice"

def test_arbitrary_code_deserialization_blocked():
    # Attempting to execute code via pickle bytecode
    malicious_pickle = pickle.dumps(ExploitPayload())
    with pytest.raises(Exception):
        load_session_data(malicious_pickle)

