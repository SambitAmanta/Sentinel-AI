"""Config service layer."""
from loader import parse_config_payload

def load_system_config(payload: str) -> dict:
    return parse_config_payload(payload)

