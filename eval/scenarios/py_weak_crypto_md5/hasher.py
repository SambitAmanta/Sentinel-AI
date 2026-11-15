"""Password hashing utility with weak MD5 cryptographic algorithm."""
import hashlib

def hash_password(password: str) -> str:
    # VULNERABILITY: Weak hash algorithm MD5 (Bandit B303 / CWE-327)
    return hashlib.md5(password.encode("utf-8")).hexdigest()

