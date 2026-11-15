# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 Laptop GPU (8GB VRAM)  
**Evaluated Systems**: Live Local SLM (`Qwen2.5-Coder-7B-Instruct`) & Deterministic Pipeline Harness  
**Scenarios**: 12 across 9 CWE classes (11 multi-file repositories, 1 single-file repo)  
**Grading Protocol**: Like-for-like evaluation against visible unit test suites and independent held-out exploit suites  

---

## 1. Executive Summary: Dual-Mode Empirical Results

| Evaluation Layer | Single-Shot Pass Rate | SentinelAI Loop Pass Rate (≤3 Attempts) | Median Latency (p50) | Tail Latency (p95) | Primary Validation Goal |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Live Local SLM (`Qwen2.5-Coder-7B`)** | **25.0%** (3/12) | **25.0%** (3/12) | **~4.13s** (single) / **~15.43s** (loop) | **~19.28s** (loop) | Real-world consumer GPU generative refactoring |
| **Deterministic Architecture Harness** | **66.7%** (8/12) | **100.0%** (12/12) | **~1.50s** (loop) | **~2.52s** (loop) | LangGraph state machine, AST context & rollback |

---

## 2. Live Local SLM Benchmark (`Qwen2.5-Coder-7B-Instruct` on RTX 5050 8GB)

Evaluated via local Ollama instance against an NVIDIA GeForce RTX 5050 (8GB VRAM) using greedy decoding (`temperature=0.0`):

| Scenario ID | Vulnerability Scenario | CWE Class | Single-Shot (Visible + Held-Out) | SentinelAI Loop (≤3 Attempts) | Iterations | Tokens Generated | Remediation Latency | Attempt 1 Failure Taxonomy |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **SCENARIO-01** | SQL Injection in User Auth | CWE-89 | `FAIL` | `FAIL` | 3 | 62 | 16,706 ms | Syntax error (SQLite `%s` vs `?` placeholder) |
| **SCENARIO-02** | SQL Injection w/ Pagination | CWE-89 | `FAIL` | `FAIL` | 3 | 73 | 17,518 ms | Syntax error (SQLite `%s` vs `?` placeholder) |
| **SCENARIO-03** | OS Command Injection in Ping | CWE-78 | `FAIL` | `FAIL` | 3 | 41 | 15,443 ms | Contract broken (`shell=True` retained) |
| **SCENARIO-04** | Command Injection w/ Telemetry | CWE-78 | `PASS` | `PASS` | 1 | 65 | 6,042 ms | None (Resolved on Attempt 1) |
| **SCENARIO-05** | Path Traversal in User Storage | CWE-22 | `FAIL` | `FAIL` | 3 | 42 | 15,408 ms | Contract broken (relative path check omitted) |
| **SCENARIO-06** | Zip Slip Archive Traversal | CWE-22 | `FAIL` | `FAIL` | 3 | 36 | 15,054 ms | Contract broken (subdirectories rejected) |
| **SCENARIO-07** | Insecure Deserialization | CWE-502 | `FAIL` | `FAIL` | 3 | 29 | 15,900 ms | Missing import (`NameError: name 'json' is not defined`) |
| **SCENARIO-08** | SSRF in Webhook Dispatcher | CWE-918 | `FAIL` | `FAIL` | 3 | 36 | 21,429 ms | Network error (`socket.gaierror: getaddrinfo failed`) |
| **SCENARIO-09** | Broken Cryptographic Hash (MD5) | CWE-327 | `PASS` | `PASS` | 1 | 46 | 5,433 ms | None (Resolved on Attempt 1) |
| **SCENARIO-10** | Hardcoded JWT Secret Key | CWE-798 | `PASS` | `PASS` | 1 | 57 | 5,503 ms | None (Resolved on Attempt 1) |
| **SCENARIO-11** | ReDoS Backtracking Regex | CWE-1333 | `FAIL` | `FAIL` | 1 | 65 | 6,036 ms | Held-out exploit failed (ReDoS vulnerability unpatched) |
| **SCENARIO-12** | XSS Template Injection | CWE-79 | `FAIL` | `FAIL` | 3 | 54 | 16,511 ms | Missing import (`NameError: name 'escape' is not defined`) |

### Empirical Observations on Live 7B SLMs
* **Single-Shot Pass Rate**: **25.0% (3/12)**. Resolves isolated cryptographic algorithm migrations (MD5 $\rightarrow$ SHA256), environment secret extractions, and argument list conversions.
* **Mean Generated Tokens**: **50.5 tokens/patch** across all 12 scenarios.
* **Measured Hardware Throughput**: **43.4 tok/s** measured on RTX 5050 8GB GPU (~5.96 GB VRAM allocated).
* **Multi-Turn Dynamics**: On Attempt 2, the model demonstrated semantic reflection (e.g., switching from `%s` to `?` upon seeing SQLite syntax errors in Attempt 1 tracebacks), but encountered target-block scope truncation on multi-line statements.

---

## 3. Empirical Failure Analysis Taxonomy (Live Model Attempt 1)

Categorization of failure modes when deploying raw 7B parameter models on code refactoring tasks:

1. **Driver & Syntax Placeholder Mismatches (2/12: Scenarios 01, 02 - CWE-89)**:
   - *Failure*: Model emitted `%s` (standard for MySQL/psycopg2) rather than `?` (required by Python `sqlite3`).
   - *Traceback*: `sqlite3.OperationalError: near "%": syntax error`.
2. **Missing Standard Library Imports (2/12: Scenarios 07, 12 - CWE-502, CWE-79)**:
   - *Failure*: Model correctly introduced `json.loads(payload)` and `html.escape(text)` inside target function bodies, but omitted `import json` / `import html`.
   - *Traceback*: `NameError: name 'json' is not defined` / `NameError: name 'escape' is not defined`.
3. **Subprocess & Path Resolution Contract Violations (3/12: Scenarios 03, 05, 06 - CWE-78, CWE-22)**:
   - *Failure*: In Scenario 03, the patch parameterized arguments but retained `shell=True`. In Scenarios 05 and 06, naive boundary checks rejected valid nested subdirectories.
4. **Mock Resolution & ReDoS Completeness (2/12: Scenarios 08, 11 - CWE-918, CWE-1333)**:
   - *Failure*: In Scenario 08, the model attempted direct HTTP connection against mock cloud metadata endpoints (`socket.gaierror`). In Scenario 11, the regex passed basic syntax tests but failed the held-out catastrophic backtracking payload.

---

## 4. Deterministic Architecture Test Harness (`--mode pipeline`)

Evaluates the LangGraph state machine, Tree-sitter symbol graph context propagation, subprocess test execution, error reflection, and rollback mechanics without LLM sampling variance:

| Scenario ID | Vulnerability Scenario | CWE Class | Multi-File | Single-Attempt Synthesis | SentinelAI Loop (≤3 Attempts) | Iterations | Latency (ms) | Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **SCENARIO-01** | SQL Injection in User Auth | CWE-89 | Yes | `PASS` | `PASS` | 1 | 1,499.7 ms | **RESOLVED** |
| **SCENARIO-02** | SQL Injection w/ Pagination | CWE-89 | Yes | `FAIL (Contract Broken)` | `PASS` | 2 | 2,464.3 ms | **RESOLVED** |
| **SCENARIO-03** | OS Command Injection in Ping | CWE-78 | Yes | `PASS` | `PASS` | 1 | 1,444.4 ms | **RESOLVED** |
| **SCENARIO-04** | Command Injection w/ Telemetry | CWE-78 | Yes | `FAIL (Contract Broken)` | `PASS` | 2 | 2,565.6 ms | **RESOLVED** |
| **SCENARIO-05** | Path Traversal in User Storage | CWE-22 | Yes | `PASS` | `PASS` | 1 | 1,480.2 ms | **RESOLVED** |
| **SCENARIO-06** | Zip Slip Archive Traversal | CWE-22 | Yes | `FAIL (Contract Broken)` | `PASS` | 2 | 2,486.3 ms | **RESOLVED** |
| **SCENARIO-07** | Insecure Deserialization | CWE-502 | Yes | `PASS` | `PASS` | 1 | 1,496.0 ms | **RESOLVED** |
| **SCENARIO-08** | SSRF in Webhook Dispatcher | CWE-918 | Yes | `FAIL (Contract Broken)` | `PASS` | 2 | 2,482.1 ms | **RESOLVED** |
| **SCENARIO-09** | Broken Cryptographic Hash (MD5) | CWE-327 | Yes | `PASS` | `PASS` | 1 | 1,468.1 ms | **RESOLVED** |
| **SCENARIO-10** | Hardcoded JWT Secret Key | CWE-798 | Yes | `PASS` | `PASS` | 1 | 1,505.0 ms | **RESOLVED** |
| **SCENARIO-11** | ReDoS Backtracking Regex | CWE-1333 | No | `PASS` | `PASS` | 1 | 1,414.1 ms | **RESOLVED** |
| **SCENARIO-12** | XSS Template Injection | CWE-79 | Yes | `PASS` | `PASS` | 1 | 1,453.0 ms | **RESOLVED** |

### Pipeline Harness Summary
* **Single-Attempt Synthesis**: **66.7% (8/12)**. Fails specifically on the 4 purpose-built contract scenarios (02, 04, 06, 08).
* **SentinelAI Autonomous Loop (≤3 Attempts)**: **100.0% (12/12)**. All 4 contract regressions introduced on Attempt 1 self-healed on Attempt 2 via traceback reflection.
* **Held-Out Exploit Verification**: **100.0% (12/12)** exploit neutralization confirmed, with no overfitting to visible tests observed.
* **Mean Iterations**: **1.33 iterations/scenario**.
* **Pipeline Latency Profile**: Median **~1.50s** (1,497.8ms) | Mean **~1.81s** (1,813.2ms) | Tail (p95) **~2.52s** (2,522.0ms).

---

## 5. Sandbox Containment & Fault-Injection Verification

SentinelAI enforces strict containment across all test executions:
1. **Subprocess Isolation (`SubprocessSandboxRunner`)**: Evaluated in fault-injection tests using timeout enforcement (<5.0s via Windows process tree termination `taskkill /F /T` / POSIX process-group kill), stripped network proxies (`HTTP_PROXY`, tokens scrubbed, `NO_PROXY=*`), and automatic workspace rollback (`PatchEngine.rollback_file`).
2. **Container Isolation (`DockerSandboxRunner`)**: Available for environments with active Docker daemons (`backend/Dockerfile.sandbox`), enforcing kernel-level filesystem isolation with `--network none`, `--memory 512m`, and `--cpus 1.0`. All fault-injection unit tests run and pass under the timeout-enforced, environment-scrubbed subprocess runner.
3. **Fault-Injection Verification**:
   - Runaway infinite loop: Terminated within `< 5.0s`.
   - Broken/corrupted patches: Prevented and rolled back with zero host filesystem modification.
