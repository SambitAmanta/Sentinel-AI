"""Curated security mitigation guidelines and remediation patterns for CWE classes."""
from typing import List, Dict, Any

CWE_KNOWLEDGE_DOCS: List[Dict[str, Any]] = [
    {
        "id": "cwe-89-sqlite",
        "cwe_id": "CWE-89",
        "title": "SQL Injection Prevention in SQLite",
        "text": """When fixing SQL injection (CWE-89) in Python with SQLite:
Never concatenate or format user input directly into SQL strings using f-strings, %, or .format().
Always use parameterized queries with the '?' parameter placeholder.
Pass query parameters as a tuple in cursor.execute(query, (param1, param2)).
Preserve existing query clauses such as LIMIT, OFFSET, ORDER BY, and pagination logic.
Example secure pattern:
query = "SELECT id, username, email FROM users WHERE username = ? AND status = 'active'"
cursor.execute(query, (username,))""",
        "metadata": {"cwe_id": "CWE-89", "category": "injection", "driver": "sqlite3"}
    },
    {
        "id": "cwe-89-relational",
        "cwe_id": "CWE-89",
        "title": "SQL Injection Prevention in Relational Databases (PostgreSQL / MySQL)",
        "text": """When fixing SQL injection (CWE-89) in PostgreSQL (psycopg2) or MySQL (PyMySQL):
Use the '%s' parameter placeholder for PostgreSQL / MySQL query binding.
Never format strings directly into queries.
Pass parameters as a tuple in cursor.execute(query, (param,)).
Example secure pattern:
query = "SELECT * FROM customers WHERE search_term = %s"
cursor.execute(query, (user_search,))""",
        "metadata": {"cwe_id": "CWE-89", "category": "injection", "driver": "psycopg2"}
    },
    {
        "id": "cwe-78-command-injection",
        "cwe_id": "CWE-78",
        "title": "OS Command Injection Prevention",
        "text": """When fixing OS Command Injection (CWE-78) in Python:
Avoid subprocess.run() or subprocess.Popen() with shell=True.
Pass arguments as a safe list of strings: subprocess.run(['cmd', arg1, arg2], shell=False).
If a shell is strictly required, validate inputs against strict allowlists or sanitize with shlex.quote().
Preserve existing telemetry prefixes, return types, and stdout/stderr capture contracts.
Example secure pattern:
subprocess.run(['ping', '-c', '1', target_host], capture_output=True, text=True, check=True)""",
        "metadata": {"cwe_id": "CWE-78", "category": "injection", "driver": "subprocess"}
    },
    {
        "id": "cwe-22-path-traversal",
        "cwe_id": "CWE-22",
        "title": "Path Traversal & Zip Slip File Security",
        "text": """When fixing Path Traversal (CWE-22) in file access or archive extraction (Zip Slip):
Use pathlib.Path to resolve absolute canonical paths: target = (base_dir / filename).resolve().
Verify that the target path is strictly contained inside the safe base directory:
In Python 3.9+: target.is_relative_to(base_dir.resolve()).
Or check: target.resolve().startswith(base_dir.resolve()).
Do not blindly strip slashes, as valid nested subdirectories should remain extractable within base_dir.
Example secure pattern:
target_path = (safe_root / user_path).resolve()
if not target_path.is_relative_to(safe_root.resolve()):
    raise PermissionError("Access denied: path traversal detected")""",
        "metadata": {"cwe_id": "CWE-22", "category": "file_security", "driver": "pathlib"}
    },
    {
        "id": "cwe-502-deserialization",
        "cwe_id": "CWE-502",
        "title": "Insecure Deserialization (Pickle / YAML)",
        "text": """When fixing Insecure Deserialization (CWE-502):
Never unpickle untrusted payloads using pickle.loads() or pickle.load(), as pickle permits arbitrary bytecode execution.
Replace pickle with safe standard formats like json.loads() or json.dumps().
For YAML files, never use yaml.load() without specifying a safe loader.
Always use yaml.safe_load(payload) or yaml.load(payload, Loader=yaml.SafeLoader).
Ensure the required standard module (import json) is present in the file.""",
        "metadata": {"cwe_id": "CWE-502", "category": "deserialization", "driver": "json_yaml"}
    },
    {
        "id": "cwe-918-ssrf",
        "cwe_id": "CWE-918",
        "title": "Server-Side Request Forgery (SSRF) Prevention",
        "text": """When fixing SSRF (CWE-918) in HTTP client requests (requests, httpx, urllib):
Parse target URLs using urllib.parse.urlparse() and enforce strict scheme allowlists (http, https).
Deny access to private and loopback IP ranges:
- 127.0.0.0/8 (localhost)
- 169.254.169.254 (Cloud metadata services: AWS, GCP, Azure)
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Private subnets)
Use ipaddress.ip_address() to check if resolved hostnames are private or loopback.
Example secure pattern:
parsed = urlparse(target_url)
if parsed.scheme not in ('http', 'https') or parsed.hostname in ('localhost', '127.0.0.1', '169.254.169.254'):
    raise ValueError("Invalid target: SSRF protection triggered")""",
        "metadata": {"cwe_id": "CWE-918", "category": "network", "driver": "urllib"}
    },
    {
        "id": "cwe-327-crypto",
        "cwe_id": "CWE-327",
        "title": "Broken Cryptographic Algorithm Upgrade",
        "text": """When fixing Weak Cryptographic Algorithms (CWE-327):
Never use MD5 (hashlib.md5) or SHA-1 (hashlib.sha1) for cryptographic integrity, signatures, or passwords.
Upgrade hashing to collision-resistant algorithms such as SHA-256 (hashlib.sha256()) or SHA-512.
For password hashing, use dedicated key derivation functions such as bcrypt, argon2, or hashlib.pbkdf2_hmac.
Example secure pattern:
digest = hashlib.sha256(data.encode('utf-8')).hexdigest()""",
        "metadata": {"cwe_id": "CWE-327", "category": "cryptography", "driver": "hashlib"}
    },
    {
        "id": "cwe-798-secrets",
        "cwe_id": "CWE-798",
        "title": "Hardcoded Credentials and Secret Keys",
        "text": """When fixing Hardcoded Credentials (CWE-798):
Never commit plaintext API keys, JWT secrets, passwords, or database credentials into source code.
Retrieve sensitive secrets dynamically from the environment using os.getenv("SECRET_NAME") or os.environ.
Provide safe defaults only for local test fixtures, or fail fast if the environment variable is unset.
Example secure pattern:
import os
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_dev_secret")""",
        "metadata": {"cwe_id": "CWE-798", "category": "credentials", "driver": "os"}
    },
    {
        "id": "cwe-1333-redos",
        "cwe_id": "CWE-1333",
        "title": "Regular Expression Denial of Service (ReDoS)",
        "text": """When fixing ReDoS (CWE-1333):
Avoid nested quantifiers like (a+)+ or overlapping repetitions like ([a-zA-Z]+)*.
Use possessive quantifiers, atomic groupings, or rewrite patterns to be deterministic and linear.
Enforce length limits on untrusted input strings before regex evaluation.
Use Python's re module with explicit character classes and bounded lengths (e.g. {1,100}).""",
        "metadata": {"cwe_id": "CWE-1333", "category": "dos", "driver": "re"}
    },
    {
        "id": "cwe-79-xss",
        "cwe_id": "CWE-79",
        "title": "Cross-Site Scripting (XSS) Template Sanitization",
        "text": """When fixing Reflected or Stored Cross-Site Scripting (CWE-79):
Never interpolate unsanitized user strings directly into HTML templates or error banners.
Use context-aware HTML escaping via html.escape(user_input, quote=True).
In Jinja2 or modern web templates, ensure auto-escaping is active.
Ensure import html is present in the file headers.""",
        "metadata": {"cwe_id": "CWE-79", "category": "xss", "driver": "html"}
    },
]
