"""Remote image proxy fetching module."""
import urllib.request

def fetch_remote_image(image_url: str) -> dict:
    # VULNERABILITY: SSRF via unvalidated remote URL request (Bandit B310 / CWE-918)
    req = urllib.request.Request(image_url, headers={"User-Agent": "ImageProxy/1.0"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return {"status": response.status, "content_type": response.headers.get("Content-Type")}

