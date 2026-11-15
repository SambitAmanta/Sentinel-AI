"""Web error presentation component."""

def format_error_banner(error_message: str) -> str:
    # VULNERABILITY: Reflected XSS string interpolation (AST Security / CWE-79)
    return f"<div class='alert-danger'>Error: <span>{error_message}</span></div>"

