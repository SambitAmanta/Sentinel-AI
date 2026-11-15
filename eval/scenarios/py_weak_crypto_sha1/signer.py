"""Message authentication signer module."""
import hashlib

def compute_payload_signature(message: str) -> str:
    # VULNERABILITY: Use of weak hash function SHA-1 (Bandit B303 / CWE-327)
    return hashlib.sha1(message.encode("utf-8")).hexdigest()

