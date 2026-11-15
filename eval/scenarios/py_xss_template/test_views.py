"""Unit tests verifying HTML escaping against XSS payloads."""
from renderer import render_user_banner
from views import get_welcome_view

def test_safe_name_rendering():
    html = render_user_banner("Alice")
    assert "Alice" in html

def test_xss_injection_defense():
    # Attack payload with script tag
    payload = "<script>alert('pwned')</script>"
    html = get_welcome_view(payload)
    assert "<script>" not in html, "XSS vulnerability: raw <script> tag rendered unescaped!"
    assert "&lt;script&gt;" in html or html.find("<") == 0

