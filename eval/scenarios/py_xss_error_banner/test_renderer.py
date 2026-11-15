from service import render_api_error

def test_render_error_banner():
    banner = render_api_error("User not found")
    assert "User not found" in banner
    assert "alert-danger" in banner

