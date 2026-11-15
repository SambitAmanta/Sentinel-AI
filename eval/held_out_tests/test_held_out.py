"""Held-out evaluation suite for SentinelAI benchmarks.
Executes independent exploit neutralization and contract preservation tests in clean subprocesses.
The agent NEVER sees or interacts with this suite during its scan-patch-verify loop.
"""
import json
import subprocess
import sys
from pathlib import Path

SCENARIO_EVAL_SCRIPTS = {
    "SCENARIO-01": """
import sys
from db import init_db, get_user_by_id
from service import authenticate_and_get_profile

conn = init_db()
# Exploit: UNION injection attack
exploit = "' UNION SELECT 'hacked', 'admin', 'superuser' --"
user = get_user_by_id(conn, exploit)
exploit_blocked = (user is None)

# Contract: Valid lookup
valid = authenticate_and_get_profile(conn, "usr_2")
contract_ok = (valid is not None and valid.get("username") == "bob" and valid.get("status") == "ACTIVE")

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-02": """
import sys
from repo import init_product_db
from routes import handle_search_request

conn = init_product_db()
# Exploit: SQL injection attempt
exploit_query = "Laptop' UNION SELECT 99, 'HACK', 0.0 --"
items = handle_search_request(conn, exploit_query, limit=5)
exploit_blocked = not any(item.get("name") == "HACK" for item in items)

# Contract: Exact pagination contract
limit1 = handle_search_request(conn, "Laptop", limit=1)
limit3 = handle_search_request(conn, "Laptop", limit=3)
contract_ok = (len(limit1) == 1 and len(limit3) == 3)

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-03": """
import sys
from client import check_server_health

# Exploit: Shell metacharacter injection
exploit_res = check_server_health("127.0.0.1; echo PWNED_FLAG")
exploit_blocked = "PWNED_FLAG" not in exploit_res.get("details", "")

# Contract: Valid server check returns status
contract_res = check_server_health("127.0.0.1")
contract_ok = contract_res.get("host") == "127.0.0.1"

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-04": """
import sys
from system import get_system_stats
from monitor import collect_health_metrics

# Exploit: Shell injection treated as safe literal argument
res = get_system_stats("safe; echo INJECTED")
exploit_blocked = (res.get("returncode") == 0 and res.get("output") == "METRIC_safe; echo INJECTED")

# Contract: Downstream telemetry contract
health = collect_health_metrics()
contract_ok = (health.get("status") == "HEALTHY" and health.get("raw") == "METRIC_UPTIME")

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-05": """
import sys
from file_service import init_storage
from api import get_report_content

init_storage()
# Exploit: Directory traversal
exploit_blocked = False
try:
    get_report_content("../../etc/passwd")
except (PermissionError, ValueError):
    exploit_blocked = True

# Contract: Valid file retrieval
content = get_report_content("welcome.txt")
contract_ok = "Hello World" in content

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-06": """
import io
import zipfile
from pathlib import Path
from archive import extract_archive
from extractor import unpack_package

# Exploit: Zip Slip attack
bio = io.BytesIO()
with zipfile.ZipFile(bio, "w") as z:
    z.writestr("../../escaped.txt", "MALICIOUS")
bio.seek(0)
Path("test_malicious.zip").write_bytes(bio.read())
Path("out_safe").mkdir(exist_ok=True)

exploit_blocked = False
try:
    extract_archive("test_malicious.zip", "out_safe")
except (PermissionError, ValueError):
    exploit_blocked = True

# Contract: Valid nested file extraction
bio2 = io.BytesIO()
with zipfile.ZipFile(bio2, "w") as z:
    z.writestr("sub/doc.txt", "SafeNested")
bio2.seek(0)
Path("test_nested.zip").write_bytes(bio2.read())
Path("out_nested").mkdir(exist_ok=True)

names = unpack_package("test_nested.zip", "out_nested")
contract_ok = "sub" in names or "doc.txt" in names or (Path("out_nested") / "sub" / "doc.txt").exists()

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-07": """
import sys
import json
from auth import verify_user_session

# Exploit: Malicious pickle payload
exploit_payload = b"cos\\nsystem\\n(S'echo EXPLOITED'\\ntR."
exploit_blocked = False
try:
    verify_user_session(exploit_payload)
except Exception:
    exploit_blocked = True

# Contract: Valid JSON session payload
valid_payload = json.dumps({"user_id": "usr_charlie", "role": "dev"}).encode("utf-8")
res = verify_user_session(valid_payload)
contract_ok = (res == "usr_charlie")

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-08": """
import sys
import requests
from dispatcher import dispatch_webhook
from webhook import notify_subscriber

# Exploit: SSRF to cloud metadata
exploit_blocked = False
try:
    dispatch_webhook("http://169.254.169.254/latest/meta-data")
except (PermissionError, ValueError):
    exploit_blocked = True

# Contract: Valid webhook mock delivery
class MockResp:
    status_code = 200
requests.get = lambda url, **kw: MockResp()
res = notify_subscriber("https://api.example.com/events")
contract_ok = (res is True)

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-09": """
import sys
from hasher import hash_password
from user import create_user_record

# Exploit: MD5 broken hash check
h = hash_password("SecretPassword123")
exploit_blocked = (len(h) == 64 and h != "5ebe2294ecd0e0f08eab7690d2a6ee69")

# Contract: User record creation
rec = create_user_record("dave", "SecretPassword123")
contract_ok = (rec.get("user") == "dave" and rec.get("hash") == h)

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-10": """
import os
from pathlib import Path

# Contract: Environment override works when set prior to token signing
os.environ["API_SECRET_KEY"] = "rotated_secret_key"
from jwt_auth import sign_token

# Exploit: Check that hardcoded secret literal is removed from config.py
config_code = Path("config.py").read_text(encoding="utf-8")
exploit_blocked = ("sk_live_9928347102938471928374" not in config_code)

token = sign_token({"user_id": "usr_007"})
contract_ok = (token == "usr_007.rotated_secret_key")

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-11": """
import time
from validator import validate_user_email

# Exploit: Catastrophic backtracking evaluated instantly (< 50ms)
t0 = time.time()
res = validate_user_email("aaaaaaaaaaaaaaaaaaaaaaaaaaaa!@bad.com")
duration_ms = (time.time() - t0) * 1000
exploit_blocked = (res is False and duration_ms < 50.0)

# Contract: Valid corporate email passes
contract_ok = (validate_user_email("alice.smith+alerts@subdomain.co.uk") is True)

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
""",

    "SCENARIO-12": """
import sys
from views import get_welcome_view

# Exploit: Dangerous HTML injection payload
exploit_html = "<script>alert('XSS')</script>"
rendered = get_welcome_view(exploit_html)
exploit_blocked = ("<script>" not in rendered and "&lt;script&gt;" in rendered)

# Contract: Dashboard structure preserved
contract_ok = ("<div class='user-banner'>" in rendered and "Welcome back" in rendered)

print(json.dumps({"passed": exploit_blocked and contract_ok, "exploit_blocked": exploit_blocked, "contract_preserved": contract_ok}))
"""
}

def evaluate_scenario_held_out(scenario_id: str, repo_dir: Path) -> dict:
    """Runs independent held-out evaluation tests against the patched scenario repo in a clean subprocess."""
    script = SCENARIO_EVAL_SCRIPTS.get(scenario_id)
    if not script:
        return {"scenario_id": scenario_id, "passed": True, "exploit_blocked": True, "contract_preserved": True, "error": None}

    cmd = [sys.executable, "-c", f"import json\n{script}"]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_dir.resolve()),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            output_lines = [l.strip() for l in proc.stdout.strip().splitlines() if l.strip().startswith("{")]
            if output_lines:
                data = json.loads(output_lines[-1])
                data["scenario_id"] = scenario_id
                data["error"] = None
                return data
            return {"scenario_id": scenario_id, "passed": False, "exploit_blocked": False, "contract_preserved": False, "error": f"Invalid JSON output: {proc.stdout}"}
        else:
            return {"scenario_id": scenario_id, "passed": False, "exploit_blocked": False, "contract_preserved": False, "error": proc.stderr or proc.stdout}
    except Exception as e:
        return {"scenario_id": scenario_id, "passed": False, "exploit_blocked": False, "contract_preserved": False, "error": str(e)}
