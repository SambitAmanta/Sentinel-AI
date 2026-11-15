"""Image proxy service layer."""
from fetcher import fetch_remote_image

def proxy_image_request(url: str) -> dict:
    return fetch_remote_image(url)

