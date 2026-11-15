"""Signature verification service layer."""
from signer import compute_payload_signature

def sign_api_token(token: str) -> str:
    return compute_payload_signature(token)

