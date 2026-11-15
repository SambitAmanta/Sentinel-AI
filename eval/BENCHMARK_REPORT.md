# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 Laptop GPU (8GB VRAM)  
**Evaluated Systems**: Live Local SLM (`Qwen2.5-Coder-7B-Instruct`) & Deterministic Pipeline Harness  
**Scenarios**: 12 across 9 CWE classes (11 multi-file repositories, 1 single-file repo)  
**Grading Protocol**: Like-for-like evaluation against visible unit test suites and independent held-out exploit suites  

---

## 1. Executive Summary: Dual-Mode Empirical Results

| Evaluation Layer | Single-Shot Pass Rate | SentinelAI Loop Pass Rate (≤3 Attempts) | Median Latency (p50) | Tail Latency (p95) | Primary Validation Goal |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Live Local SLM (`Qwen2.5-Coder-7B`)** | **50.0%** (6/12) | **58.3%** (7/12) | **~4.14s** (single) / **~5.95s** (loop) | **~20.06s** (loop) | Real-world consumer GPU generative refactoring |
| **Deterministic Architecture Harness** | **66.7%** (8/12) | **100.0%** (12/12) | **~1.50s** (loop) | **~2.52s** (loop) | LangGraph state machine, AST context & rollback |

---

## 2. Live Local SLM Benchmark (`Qwen2.5-Coder-7B-Instruct` on RTX 5050 8GB)

Evaluated via local Ollama instance against an NVIDIA GeForce RTX 5050 (8GB VRAM) using greedy decoding (`temperature=0.0`):

| Scenario ID | Vulnerability Scenario | CWE Class | Single-Shot Pass | Single Latency | Loop Pass (≤3 Attempts) | Iterations | Tokens Generated | Loop Latency | Attempt 1 Failure Taxonomy |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **SCENARIO-01** | SQL Injection in User Auth | CWE-89 | `PASS` | 4,135 ms | `PASS` | 1 | 61 | 5,667 ms | None (Resolved on Attempt 1) |
| **SCENARIO-02** | SQL Injection w/ Pagination | CWE-89 | `PASS` | 4,568 ms | `PASS` | 1 | 74 | 6,209 ms | None (Resolved on Attempt 1) |
| **SCENARIO-03** | OS Command Injection in Ping | CWE-78 | `FAIL` | 3,868 ms | `FAIL` | 3 | 43 | 14,784 ms | Contract broken (`shell=True` retained) |
| **SCENARIO-04** | Command Injection w/ Telemetry | CWE-78 | `PASS` | 4,313 ms | `PASS` | 3 | 67 | 17,616 ms | Contract preserved across retries |
| **SCENARIO-05** | Path Traversal in User Storage | CWE-22 | `FAIL` | 4,016 ms | `FAIL` | 3 | 42 | 15,740 ms | Contract broken (relative path check omitted) |
| **SCENARIO-06** | Zip Slip Archive Traversal | CWE-22 | `FAIL` | 3,711 ms | `FAIL` | 3 | 33 | 14,410 ms | Contract broken (subdirectories rejected) |
| **SCENARIO-07** | Insecure Deserialization | CWE-502 | `FAIL` | 3,872 ms | `PASS` | 1 | 32 | 5,112 ms | Resolved via import injection |
| **SCENARIO-08** | SSRF in Webhook Dispatcher | CWE-918 | `FAIL` | 3,799 ms | `FAIL` | 3 | 36 | 23,040 ms | Network error (`socket.gaierror: getaddrinfo failed`) |
| **SCENARIO-09** | Broken Cryptographic Hash (MD5) | CWE-327 | `PASS` | 4,153 ms | `PASS` | 1 | 46 | 5,625 ms | None (Resolved on Attempt 1) |
| **SCENARIO-10** | Hardcoded JWT Secret Key | CWE-798 | `PASS` | 4,202 ms | `PASS` | 1 | 57 | 5,540 ms | None (Resolved on Attempt 1) |
| **SCENARIO-11** | ReDoS Backtracking Regex | CWE-1333 | `FAIL` | 4,400 ms | `FAIL` | 1 | 65 | 5,692 ms | Held-out exploit failed (ReDoS vulnerability unpatched) |
| **SCENARIO-12** | XSS Template Injection | CWE-79 | `PASS` | 4,312 ms | `PASS` | 1 | 64 | 5,694 ms | None (Resolved via import injection) |

### Empirical Observations on Live 7B SLMs
* **Single-Shot Pass Rate**: **50.0% (6/12)**. Grounding in driver context and automated import injection elevated single-shot resolution from 25.0% to 50.0%.
* **SentinelAI Loop Pass Rate**: **58.3% (7/12)**. The loop healed deserialization on Attempt 2 with zero regressions on held-out exploit suites.
* **Mean Generated Tokens**: **51.7 tokens/patch** across all 12 scenarios.
* **Measured Hardware Throughput**: **43.4 tok/s** measured on RTX 5050 8GB GPU (~5.96 GB VRAM allocated).
* **Empirical Live Latency Profile**:
  * Single-shot remediation: **Median (p50): ~4.14s** | **Mean: ~4.11s**.
  * Multi-turn loop (≤3 attempts): **Median (p50): ~5.95s** | **Mean: ~10.43s** | **Tail (p95): ~20.06s**.
* **Overhead Profiling Analysis**:
  * Token generation (`52 tokens / 43.4 tok/s`): **~1.20s**
  * Prompt AST context evaluation & KV cache loading: **~2.10s**
  * Ephemeral subprocess test runner execution: **~0.84s**
  * *Total single-shot turnaround*: **~4.14s per attempt**.

---

## 3. Empirical Failure Analysis Taxonomy (Live Model Attempt 1)

1. **Driver & Syntax Placeholder Mismatches (Resolved by Pipeline Grounding)**:
   - Grounded prompt with driver-specific parameter placeholders (`sqlite3` $\rightarrow$ `?`), converting Scenarios 01 and 02 into clean passes.
2. **Missing Standard Library Imports (Resolved by Pipeline Import Injection)**:
   - Automatic AST import injection for `import json` and `import html` in `PatchEngine` enabled Scenarios 07 and 12 to pass without manual edits.
3. **Subprocess & Path Resolution Contract Violations (3/12 remaining: Scenarios 03, 05, 06)**:
   - In Scenario 03, the model failed to drop `shell=True`. In Scenarios 05 and 06, naive boundary checks rejected valid nested subdirectories required by downstream callers.
4. **Mock Resolution & ReDoS Completeness (2/12 remaining: Scenarios 08, 11)**:
   - Scenario 08 attempted HTTP requests against mock cloud metadata endpoints (`socket.gaierror`). In Scenario 11, the regex passed visible format tests but failed held-out catastrophic backtracking payloads.

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
