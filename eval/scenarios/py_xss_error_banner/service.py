"""Error presentation service layer."""
from renderer import format_error_banner

def render_api_error(msg: str) -> str:
    return format_error_banner(msg)

