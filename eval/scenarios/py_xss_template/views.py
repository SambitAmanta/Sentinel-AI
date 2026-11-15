"""View presenter rendering banner."""
from renderer import render_user_banner

def get_welcome_view(name: str) -> str:
    return render_user_banner(name)

