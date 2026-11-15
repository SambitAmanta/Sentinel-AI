"""HTML template renderer with reflected cross-site scripting flaw."""

def render_user_banner(user_name: str) -> str:
    # VULNERABILITY: Reflected XSS / CWE-79 unescaped HTML interpolation
    return f"<div class='user-banner'>Welcome back, <span>{user_name}</span></div>"

