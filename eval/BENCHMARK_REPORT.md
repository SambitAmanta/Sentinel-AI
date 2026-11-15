# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 (8GB VRAM)  
**Execution Timestamp**: 2026-11-15 13:00:34  
**Benchmark Target**: Single-Shot (1 Attempt) vs SentinelAI Self-Healing (≤3 Attempts with Test Feedback)  
**Total Scenarios**: 12 across 9 CWE classes (11 multi-file repositories)  

---

## 1. Executive Summary

| Metric | Single-Shot Baseline (1 Attempt) | SentinelAI Autonomous Loop (≤3 Attempts) | Improvement / Engineering Gain |
| :--- | :--- | :--- | :--- |
| **Test Pass Rate** | **66.7%** (8/12) | **100.0%** (12/12) | **+33.3% autonomous remediation gain** |
| **Held-Out Verification** | **66.7%** (fails downstream contracts) | **100.0%** (12/12 exploit-neutralized) | **100% verified security & contract preservation** |
| **Test Regressions** | **33.3%** (4 regressions introduced) | **0.0%** (Verified in Sandbox + Held-Out) | **100% containment of broken patches** |
| **Mean Iterations** | 1.00 (Single-shot, static) | **1.33 iterations** | **Active reflection on Pytest failure traces** |
| **Median Latency (p50)**| ~143.2 ms | **1748.3 ms (~1.7s)** | Rapid deterministic local refactoring |
| **Tail Latency (p95)** | N/A | **3400.9 ms (~3.4s)** | Under ~3.5s even on 2-turn retries |

---

## 2. Experimental Methodology

### Baseline Definition (Single-Shot: 1 Attempt)
- **Model**: `Qwen2.5-Coder-7B-Instruct` (Q4_K_M via Ollama) with greedy decoding (`temperature=0.0`) for zero-variance deterministic evaluation.
- **Protocol**: Codebase AST indexing and static vulnerability scan provide targeted finding. The model generates a patch in a single shot without sandbox execution or error feedback.
- **Grading**: Both visible repository unit tests and independent held-out evaluation tests run. If either fails, the patch is scored as failed.
- **Why Single-Shot Fails (66.7%)**: On multi-file repositories with contract dependencies, single-shot generation produces plausible-looking security fixes that violate existing API contracts.

### Designed Contract-Preservation Scenarios
- **Scenarios 02, 04, 06, and 08** were deliberately constructed with downstream contract dependencies:
  - `SCENARIO-02` (CWE-89): Tests preservation of the `LIMIT` pagination parameter while parameterizing raw SQL.
  - `SCENARIO-04` (CWE-78): Tests preservation of the telemetry `METRIC_` prefix contract consumed by downstream monitors.
  - `SCENARIO-06` (CWE-22): Tests preservation of multi-level subdirectory archive extraction while defending against `../../` Zip Slip.
  - `SCENARIO-08` (CWE-918): Tests cloud metadata protection (`169.254.169.254`) while allowing public HTTP/HTTPS endpoints.

### SentinelAI Self-Healing Loop (≤3 Attempts)
- **Architecture**: LangGraph state machine coordinating Tree-sitter AST symbol analysis, Bandit static scanning, and an isolated sandbox test runner.
- **Self-Healing Loop**: If a patch fails sandbox verification, SentinelAI extracts the pytest failure summary and stack trace, rolls back the failed modification to ensure a pristine working tree, and passes the error trace back to the patch synthesizer.
- **Result (100.0%)**: All 4 contract regressions introduced on Attempt 1 were self-healed on Attempt 2, achieving 100% test pass rate with 0 regressions.

---

## 3. Scenario-by-Scenario Empirical Breakdown

| ID | Vulnerability Scenario | CWE Class | Multi-File | Single-Shot | SentinelAI | Held-Out | Iterations | Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SCENARIO-01 | SQL Injection in User Auth | `CWE-89` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1777.9 ms |
| SCENARIO-02 | SQL Injection w/ Pagination Regression | `CWE-89` | Yes | `FAIL (Regression)` | `PASS` | `VERIFIED` | **2** | 3226.1 ms |
| SCENARIO-03 | OS Command Injection in Network Ping | `CWE-78` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1640.0 ms |
| SCENARIO-04 | Command Injection w/ Subprocess Contract | `CWE-78` | Yes | `FAIL (Regression)` | `PASS` | `VERIFIED` | **2** | 3562.1 ms |
| SCENARIO-05 | Path Traversal in User Storage | `CWE-22` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1784.1 ms |
| SCENARIO-06 | Zip Slip Archive Directory Traversal | `CWE-22` | Yes | `FAIL (Regression)` | `PASS` | `VERIFIED` | **2** | 3269.0 ms |
| SCENARIO-07 | Insecure Deserialization via Pickle | `CWE-502` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1695.1 ms |
| SCENARIO-08 | SSRF in Webhook Dispatcher | `CWE-918` | Yes | `FAIL (Regression)` | `PASS` | `VERIFIED` | **2** | 3084.2 ms |
| SCENARIO-09 | Broken Cryptographic Hash Algorithm | `CWE-327` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1675.2 ms |
| SCENARIO-10 | Hardcoded JWT Secret Key | `CWE-798` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1718.7 ms |
| SCENARIO-11 | ReDoS Catastrophic Backtracking | `CWE-1333` | No | `PASS` | `PASS` | `VERIFIED` | **1** | 1686.2 ms |
| SCENARIO-12 | Cross-Site Scripting Template Injection | `CWE-79` | Yes | `PASS` | `PASS` | `VERIFIED` | **1** | 1716.7 ms |

---

## 4. Latency Distribution (Local Hardware)

- **Minimum Remediation Time**: 1640.0 ms
- **p50 (Median Latency)**: **1748.3 ms (~1.7s)**
- **Mean Latency**: **2236.3 ms**
- **p95 (95th Percentile)**: **3400.9 ms (~3.4s)**
- **Maximum Remediation Time**: 3562.1 ms

---

## 5. Sandbox Containment & Fault-Injection Verification

SentinelAI's execution sandbox enforces strict isolation against malicious code or runaway execution:
1. **Container Isolation (`DockerSandboxRunner`)**: Supports running test suites inside ephemeral Docker containers (`backend/Dockerfile.sandbox`) with `--network none`, `--memory 512m`, and `--cpus 1.0`.
2. **Subprocess Isolation (`SubprocessSandboxRunner`)**: For environments without active Docker daemons, uses temporary directory isolation with stripped network proxies (`HTTP_PROXY`, tokens scrubbed, `NO_PROXY=*`), Windows process tree termination (`taskkill /F /T /PID`), and workspace boundary validation.
3. **Fault-Injection Verification**:
   - Runaway infinite loop: Terminated within `< 5.0s`.
   - Out-of-scope host file writes: Prevented and rolled back with zero host filesystem modification.
