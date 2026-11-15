"""Event subscriber handling notifications."""
from dispatcher import dispatch_webhook

def notify_subscriber(endpoint_url: str) -> bool:
    res = dispatch_webhook(endpoint_url)
    return res["status_code"] == 200

