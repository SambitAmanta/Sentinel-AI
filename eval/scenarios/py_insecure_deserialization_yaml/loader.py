"""Configuration loader module with unsafe YAML deserialization."""
import yaml
from typing import Dict, Any

def parse_config_payload(payload: str) -> Dict[str, Any]:
    # VULNERABILITY: Insecure YAML deserialization (Bandit B506 / CWE-502)
    config = yaml.load(payload, Loader=yaml.Loader)
    if not isinstance(config, dict):
        raise TypeError("Configuration must be a dictionary")
    return config

