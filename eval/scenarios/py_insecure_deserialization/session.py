"""User session store with insecure pickle deserialization."""
import pickle
from typing import Dict, Any

def load_session_data(raw_payload: bytes) -> Dict[str, Any]:
    # VULNERABILITY: Insecure Deserialization via pickle.loads (Bandit B301 / CWE-502)
    session = pickle.loads(raw_payload)
    if not isinstance(session, dict):
        raise TypeError("Session must be a dictionary")
    return session

