"""Unit tests checking SSRF defense against cloud metadata and private networks."""
import pytest
import requests
from dispatcher import dispatch_webhook
from webhook import notify_subscriber

def test_valid_webhook_delivery(monkeypatch):
    class MockResp:
        status_code = 200
    monkeypatch.setattr(requests, "get", lambda url, **kw: MockResp())

    ok = notify_subscriber("https://api.example.com/callback")
    assert ok is True

def test_cloud_metadata_ssrf_blocked():
    # Attempting to query cloud metadata IP (169.254.169.254)
    with pytest.raises((ValueError, PermissionError)):
        dispatch_webhook("http://169.254.169.254/latest/meta-data/")

