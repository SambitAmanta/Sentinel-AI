# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 Laptop GPU (8GB VRAM)  
**Evaluated Systems**: Live Local SLM (`Qwen2.5-Coder-7B-Instruct` via Ollama) & Deterministic Architecture Pipeline Harness  
**Benchmark Suite**: 20 Scenarios across 9 CWE classes partitioned into:
- **Development Set**: 12 Scenarios (11 multi-file repositories, 1 single-file repo)
- **Fresh Unseen Evaluation Set**: 8 Scenarios (8 multi-file repositories)
**Grading Protocol**: Like-for-like evaluation against visible repo unit tests and independent held-out exploit suites (`eval/held_out_tests/test_held_out.py`) executed in isolated subprocesses.

---

## 1. Executive Summary: Empirical Performance Across Datasets

| Dataset / Evaluation Layer | Scenarios | Single-Shot Pass Rate (Attempt 1) | SentinelAI Loop Pass Rate (≤3 Attempts) | Healing Gain | Median Latency (p50) | Tail Latency (p95) | Primary Validation Goal |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Live SLM: Fresh Unseen Eval Set** | 8 | **62.5%** (5/8) | **87.5%** (7/8) | **+2 scenarios** (5/8 → 7/8) | **~5.9s** (5,856.5 ms) | **~18.0s** (17,986.5 ms) | Evaluates unseen scenarios from same CWE families |
| **Live SLM: Development Set** | 12 | **50.0%** (6/12) | **58.3%** (7/12) | **+1 scenario** (6/12 → 7/12) | **~6.3s** (6,307.0 ms) | **~20.6s** (20,584.1 ms) | Evaluates purpose-built contract bounds |
| **Live SLM: Combined Full Suite** | **20** | **55.0%** (11/20) | **70.0%** (14/20) | **+3 scenarios** (11/20 → 14/20) | **~6.0s** (6,026.0 ms) | **~18.6s** (18,605.4 ms) | Full consumer GPU generative refactoring |
| **Deterministic Pipeline Harness (Dev)** | 12 | **66.7%** (8/12) | **100.0%** (12/12) | **+4 scenarios** (8/12 → 12/12) | **~2.09s** (2,088.1 ms) | **~3.44s** (3,441.6 ms) | Validates orchestration, AST context & rollback |
| **Deterministic Pipeline Harness (Eval)** | 8 | **87.5%** (7/8) | **100.0%** (8/8) | **+1 scenario** (7/8 → 8/8) | **~2.05s** (2,047.3 ms) | **~4.01s** (4,013.6 ms) | Deterministic generalization verification |

---

## 2. Experimental Methodology & Rigorous Evaluation Protocol

### 2.1 Unified Trajectory Derivation (Zero Inter-Run Contradictions)
In earlier revisions, running the Single-Shot Baseline and the Self-Healing Loop as two separate, independent invocations introduced sampling and execution variance on local GPU inference. To establish scientific consistency:
- **Attempt 1 Equivalence**: The single-shot baseline is derived strictly from **Attempt 1 of the agent loop**.
- **Loop Halting vs Held-Out Post-Grading**: The agent loop halts when Attempt 1 passes **visible repository tests and the post-patch Security Gate**. Independent **held-out exploit tests are graded strictly post-hoc** (the agent never observes or executes them during its loop).
- **Consistent Results by Construction**:
  - If Attempt 1 satisfies visible unit tests and the Security Gate, the loop halts immediately at `iteration 1`. Held-out tests are then evaluated on the resulting repository state:
    - If held-out tests pass: both Single-Shot and SentinelAI Loop are graded `PASS` at 1 iteration.
    - If held-out tests fail (as observed in Scenario 11 ReDoS, where the regex passed visible format tests and the security gate did not catch catastrophic backtracking): both Single-Shot and SentinelAI Loop are graded `FAIL` at 1 iteration.
  - If Attempt 1 fails visible unit tests or the Security Gate, Single-Shot is definitively marked `FAIL`. The agent then reflects on the failure traceback across Attempts 2 and 3.
  - If the agent succeeds on Attempt 2 or 3 and passes post-hoc held-out tests, Single-Shot is `FAIL` and SentinelAI Loop is `PASS` (healed on retry).
  - Scenarios where single-shot fails while the loop reports 1 iteration, or where single-shot passes while the loop reports multiple iterations, are eliminated by design.

### 2.2 Dev-Set vs Fresh Unseen Evaluation Partitioning
To prevent development-set overfitting, SentinelAI partitions its benchmark suite into two independent tiers:
1. **Development Set (12 Scenarios)**: Contains 4 purpose-built contract-preservation regression tests (Scenarios 02, 04, 06, 08) designed to trip naive zero-shot models, evaluating pagination contracts, telemetry string formats, Zip Slip directory bounds, and cloud metadata protections.
2. **Fresh Unseen Evaluation Set (8 Scenarios, Scenarios 13–20)**: Built after all pipeline optimizations were locked down. Covers unseen scenarios from the same 8 CWE families (customer search SQLi, archive backup command injection, document download path traversal, YAML insecure deserialization, hardcoded DB credentials, SHA-1 weak cryptography, image proxy SSRF, and reflected XSS error banners).

---

## 3. Live Local SLM Benchmark: Fresh Unseen Evaluation Set (8 Scenarios)

Evaluated via local Ollama running `Qwen2.5-Coder-7B-Instruct` on an NVIDIA GeForce RTX 5050 (8GB VRAM) with greedy decoding (`temperature=0.0`):

| Scenario ID | Vulnerability Scenario | CWE Class | Multi-File | Single-Shot (Attempt 1) | Loop Pass (≤3 Attempts) | Iterations | Latency (ms) | Attempt 1 Status & Autonomous Reflection |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **SCENARIO-13** | Customer Search SQLi | CWE-89 | Yes | `FAIL` | `FAIL` | 3 | 16,529 ms | Subsumed execute mismatch (see Known Limitations) |
| **SCENARIO-14** | Archive Backup Command Injection | CWE-78 | Yes | `FAIL` | `PASS` | 3 | 17,614 ms | **Healed on Attempt 3**: Converted `shell=True` to safe argument vector |
| **SCENARIO-15** | Document Download Path Traversal | CWE-22 | Yes | `PASS` | `PASS` | 1 | 5,769 ms | **Resolved on Attempt 1**: Implemented `.resolve()` & `.is_relative_to()` |
| **SCENARIO-16** | YAML Insecure Deserialization | CWE-502 | Yes | `PASS` | `PASS` | 1 | 5,345 ms | **Resolved on Attempt 1**: Switched `yaml.load` to `yaml.safe_load` |
| **SCENARIO-17** | Hardcoded Database Password | CWE-798 | Yes | `PASS` | `PASS` | 1 | 5,339 ms | **Resolved on Attempt 1**: Migrated static secret to `os.getenv` |
| **SCENARIO-18** | SHA-1 Weak Crypto Upgrade | CWE-327 | Yes | `PASS` | `PASS` | 1 | 5,487 ms | **Resolved on Attempt 1**: Upgraded hash digest routine to `hashlib.sha256` |
| **SCENARIO-19** | Image Proxy SSRF | CWE-918 | Yes | `FAIL` | `PASS` | 3 | 18,187 ms | **Healed on Attempt 3**: Added URL parse boundary checking for metadata IPs |
| **SCENARIO-20** | Reflected XSS Error Banner | CWE-79 | Yes | `PASS` | `PASS` | 1 | 5,944 ms | **Resolved on Attempt 1**: Escaped template string via generic `import html` |

### Key Fresh Evaluation Findings:
- **Autonomous Remediation Gain**: **+2 scenarios** (Single-shot 5/8 = 62.5% $\rightarrow$ Loop 7/8 = 87.5%).
- **Multi-Turn Traceback Healing**: The agent successfully self-healed **2 out of the 3 failed initial scenarios** (Scenario 14 command injection and Scenario 19 SSRF) by ingesting Pytest tracebacks and refining the patch.
- **Generalization Confirmed**: The pipeline and local SLM generalize effectively to unseen instances across the same CWE families without scenario-specific prompt engineering.

---

## 4. Live Local SLM Benchmark: Development Set (12 Scenarios)

Evaluated under the exact same hardware and greedy decoding parameters:

| Scenario ID | Vulnerability Scenario | CWE Class | Single-Shot (Attempt 1) | Loop Pass (≤3 Attempts) | Iterations | Latency (ms) | Attempt 1 Status & Remediation Analysis |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **SCENARIO-01** | SQL Injection in User Auth | CWE-89 | `PASS` | `PASS` | 1 | 6,108 ms | **Resolved on Attempt 1**: Driver grounding (`sqlite3` $\rightarrow$ `?`) |
| **SCENARIO-02** | SQL Injection w/ Pagination | CWE-89 | `PASS` | `PASS` | 1 | 6,506 ms | **Resolved on Attempt 1**: Parameterized query preserving `LIMIT` contract |
| **SCENARIO-03** | OS Command Injection in Ping | CWE-78 | `FAIL` | `FAIL` | 3 | 15,990 ms | Failed: Model retained `shell=True` across retries |
| **SCENARIO-04** | Command Injection w/ Telemetry | CWE-78 | `FAIL` | `PASS` | 3 | 18,358 ms | **Healed on Attempt 3**: Preserved `METRIC_` string prefix contract |
| **SCENARIO-05** | Path Traversal in User Storage | CWE-22 | `FAIL` | `FAIL` | 3 | 16,914 ms | Failed: Canonical path check omitted boundary containment |
| **SCENARIO-06** | Zip Slip Archive Traversal | CWE-22 | `FAIL` | `FAIL` | 3 | 14,818 ms | Failed: Naive check rejected valid nested subdirectory extraction |
| **SCENARIO-07** | Insecure Deserialization (Pickle) | CWE-502 | `PASS` | `PASS` | 1 | 5,326 ms | **Resolved on Attempt 1**: Generic resolver injected `import json` |
| **SCENARIO-08** | SSRF in Webhook Dispatcher | CWE-918 | `FAIL` | `FAIL` | 3 | 23,305 ms | Failed: Connection error attempting live DNS resolution in test fixture |
| **SCENARIO-09** | Broken Crypto Hash (MD5) | CWE-327 | `PASS` | `PASS` | 1 | 5,657 ms | **Resolved on Attempt 1**: Upgraded MD5 hash to collision-resistant SHA-256 |
| **SCENARIO-10** | Hardcoded JWT Secret Key | CWE-798 | `PASS` | `PASS` | 1 | 5,790 ms | **Resolved on Attempt 1**: Converted hardcoded secret to `os.getenv` retrieval |
| **SCENARIO-11** | ReDoS Backtracking Regex | CWE-1333 | `FAIL` | `FAIL` | 1 | 5,800 ms | Failed: Security Gate / Held-Out caught unpatched catastrophic backtracking |
| **SCENARIO-12** | XSS Template Injection | CWE-79 | `PASS` | `PASS` | 1 | 5,787 ms | **Resolved on Attempt 1**: Generic resolver injected `import html` |

### Key Development Set Findings:
- **Single-Shot Resolution**: **50.0% (6/12)**. Grounding in driver syntax and automatic standard library import injection doubled zero-shot success from the earlier 25.0% baseline.
- **Loop Resolution**: **58.3% (7/12)**. Scenario 04 healed on Attempt 3 after reflecting on traceback failures from broken telemetry format contracts.
- **Contract Boundary Tripwires**: Scenarios 03, 05, 06, and 08 highlight the current architectural limits of 7B parameter models on deeply nested boundary contracts without multi-file tool-calling capabilities.

---

## 5. Combined Benchmark Summary (20 Scenarios across 9 CWEs)

Combining the Development Set and Fresh Unseen Evaluation Set provides a comprehensive view of real-world SLM capability on consumer hardware:

- **Combined Single-Shot Baseline**: **`55.0%` (11/20)**
- **Combined SentinelAI Self-Healing Loop**: **`70.0%` (14/20)**
- **Autonomous Remediation Gain**: **`+3 scenarios`** (11/20 → 14/20, healed on retry: Scenarios 04, 14, 19)
- **Held-Out Exploit Neutralization**: **`70.0%` (14/20)**
- **Mean Generated Tokens**: **`52.3` tokens/patch**
- **Median Remediation Latency (p50)**: **`~6.0s`** (6,026.0 ms)
- **Tail Latency (p95)**: **`~18.6s`** (18,605.4 ms) across multi-turn self-healing loops

---

## 6. Hardware Profiling & Latency Breakdown (RTX 5050 8GB VRAM)

Measurements extracted directly from Ollama response telemetry (`eval_duration`, `prompt_eval_duration`, `load_duration`) and system timers on local hardware, accounting for the full ~5.8s – 6.3s per-attempt execution:

| Component | Duration | Description & Engineering Profile |
| :--- | :---: | :--- |
| **Model Token Generation (GPU Compute)** | **~1,005 ms** (~1.00s) | Raw GPU tensor core decoding of ~54 tokens at 43.4–62.1 tok/s |
| **Prompt AST Context Evaluation (GPU Compute)** | **~91 – 200 ms** (~0.15s) | Processing Tree-sitter AST symbol slice, callers, and driver context |
| **Model Residency Load Duration (Warm VRAM)** | **~5.2 ms** | Model weights resident in GPU VRAM (~5.96 GB allocated) |
| **Ollama Grammar JSON Sampling & IPC Overhead** | **~3,172 ms** (~3.17s) | Grammar-constrained JSON state machine validation & local HTTP serialization |
| **Subprocess Pytest Runner Execution** | **~987 ms** (~0.99s) | Ephemeral process spawn, test execution, and JSON report generation |
| **Static Vulnerability Scanning (Initial + Security Gate)** | **~584 ms** (~0.58s) | Initial Bandit scan (~302ms) + post-patch Security Gate re-scan (~282ms) |
| **Tree-sitter CST Call Graph & Patch Engine** | **~3.2 ms** (~0.01s) | AST symbol extraction, diffing, and generic `sys.stdlib_module_names` resolution |
| **Total Turnaround Time (Per Attempt)** | **~5.8s – 6.3s** | Total end-to-end turnaround per self-correction iteration (Median ~6.0s) |

---

## 7. Pipeline Engineering Upgrades Addressing Reviewer Inquiries

### 7.1 Generic Standard Library Import Resolver (`PatchEngine`)
Rather than relying on a hardcoded dictionary for specific modules, SentinelAI implements a **generic stdlib import resolver**:
- Inspects `sys.stdlib_module_names` (all 305 Python standard library modules).
- Automatically discovers unimported module attribute calls in the generated replacement code (e.g., `json.loads`, `html.escape`, `hashlib.sha256`, `urllib.parse.urlparse`).
- Uses multiline regex matching (`^\s*(?:import\s+{mod}\b|from\s+{mod}\b)`) to confirm the module is not already imported at the module level.
- Automatically prepends missing top-level imports directly below docstrings, preventing runtime `NameError` regressions.

### 7.2 Post-Patch Security Verification Gate (`node_verify_in_sandbox`)
To prevent "tests pass but exploit persists" vulnerabilities (such as ReDoS regex patterns or remaining security warnings):
- After unit tests pass in the sandbox, SentinelAI triggers an automatic static re-scan of the repository using Bandit and AST security rules.
- Confirms that the target vulnerability finding (`check_id` and severity) was genuinely eliminated.
- If the vulnerability is still detected, the patch is rejected, an actionable error message is injected into `state.last_test_error`, and the agent retries.

### 7.3 Multi-Line Execute Subsumption
When the SLM generates parameterized database calls (e.g. `cursor.execute(sql, (params,))`), it often includes the execution call in its replacement. `PatchEngine` scans trailing lines to automatically subsume redundant parameterless `cursor.execute(sql)` calls, preventing duplicate query executions.

### 7.4 Known Limitations & Evaluation Isolation
- **Scenario 13 Subsumed Execute Mismatch (`PatchEngine`)**: In Scenario 13 (CWE-89 Customer Search), the model generated parameterized SQL but redundant execution subsumption had a mismatch with the target code line format. In keeping with clean evaluation methodology, this was left deliberately unfixed so that the fresh evaluation set remained genuinely withheld and untuned.
- **Single-File ReDoS Detection Boundary (Scenario 11)**: In Scenario 11, the model-generated regex satisfied visible format tests, but static analyzers do not automatically detect polynomial backtracking without dynamic regex fuzzers, resulting in post-hoc held-out failure.

---

## 8. Deterministic Architecture Test Harness (`--mode pipeline`)

Evaluates the LangGraph state machine, Tree-sitter symbol graph context propagation, subprocess test execution, error reflection, and rollback mechanics without LLM sampling variance:

| Metric | Development Set (12 Scenarios) | Fresh Evaluation Set (8 Scenarios) | Full Combined Suite (20 Scenarios) |
| :--- | :---: | :---: | :---: |
| **Single-Shot Pass Rate** | **66.7%** (8/12) | **87.5%** (7/8) | **75.0%** (15/20) |
| **SentinelAI Loop Pass Rate** | **100.0%** (12/12) | **100.0%** (8/8) | **100.0%** (20/20) |
| **Held-Out Exploit Pass Rate** | **100.0%** (12/12) | **100.0%** (8/8) | **100.0%** (20/20) |
| **Mean Iterations** | 1.33 iters/scenario | 1.25 iters/scenario | 1.30 iters/scenario |
| **Median Latency (p50)** | **~2.09s** (2,088.1 ms) | **~2.05s** (2,047.3 ms) | **~2.07s** |
| **Tail Latency (p95)** | **~3.44s** (3,441.6 ms) | **~4.01s** (4,013.6 ms) | **~3.78s** |

---

## 9. Sandbox Containment & Fault-Injection Verification

SentinelAI enforces dual-layer isolation:
1. **Subprocess Sandbox Runner (`SubprocessSandboxRunner`)**: Evaluated in fault-injection tests using timeout enforcement (<5.0s via Windows process tree termination `taskkill /F /T` / POSIX process-group kill), stripped network proxies (`HTTP_PROXY`, tokens scrubbed, `NO_PROXY=*`), and automatic workspace rollback (`PatchEngine.rollback_file`).
2. **Container Sandbox Runner (`DockerSandboxRunner`)**: Available when a Docker daemon is active (`backend/Dockerfile.sandbox`), providing operating-system-level filesystem isolation with `--network none`, `--memory 512m`, and `--cpus 1.0`. All fault-injection unit tests run and pass under the timeout-enforced, environment-scrubbed subprocess runner.
