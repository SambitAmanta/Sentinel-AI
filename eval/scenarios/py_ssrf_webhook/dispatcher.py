"""Webhook dispatcher with Server-Side Request Forgery vulnerability."""
import requests
from typing import Dict, Any

def dispatch_webhook(target_url: str) -> Dict[str, Any]:
    # VULNERABILITY: SSRF (CWE-918) - Fetching arbitrary user-supplied URL without host validation
    resp = requests.get(target_url, timeout=5)
    return {"status_code": resp.status_code, "url": target_url}

