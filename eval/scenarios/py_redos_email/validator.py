"""Email validator with catastrophic backtracking Regular Expression."""
import re

# VULNERABILITY: Catastrophic backtracking regex / ReDoS (CWE-1333)
EMAIL_PATTERN = r"^([a-zA-Z0-9_]+)+@([a-zA-Z0-9_]+)+\.com$"

def validate_user_email(email_str: str) -> bool:
    return bool(re.match(EMAIL_PATTERN, email_str))

