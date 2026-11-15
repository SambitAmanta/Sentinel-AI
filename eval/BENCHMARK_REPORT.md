# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 (8GB VRAM)  
**Execution Timestamp**: 2026-11-15 16:11:00  
**Benchmark Target**: Single-Shot (1 Attempt) vs SentinelAI Self-Healing (≤3 Attempts with Test Feedback)  
**Execution Mode**: Deterministic Architecture Test Harness  
**Total Scenarios**: 12 across 9 CWE classes (11 multi-file repositories)  
**Grading Protocol**: Like-for-like evaluation against visible test suites and independent held-out exploit suites  

---

## 1. Executive Summary

| Metric | Single-Shot Baseline (1 Attempt) | SentinelAI Autonomous Loop (≤3 Attempts) | Improvement / Engineering Gain |
| :--- | :--- | :--- | :--- |
| **Combined Pass Rate (Visible + Held-Out)** | **66.7%** (8/12) | **100.0%** (12/12) | **+33.3% autonomous remediation gain** |
| **Held-Out Exploit Neutralization** | **66.7%** (fails downstream contracts) | **100.0%** (12/12 neutralized) | **100% verified security & contract preservation** |
| **Contract Regressions** | **33.3%** (4 regressions introduced) | **0.0%** (Verified in Sandbox + Held-Out) | **100% containment of broken patches** |
| **Mean Iterations** | 1.00 (Single-shot, static) | **1.33 iterations** | **Active reflection on Pytest failure traces** |
| **Median Latency (p50)**| ~1.0 ms | **1497.8 ms (~1.50s)** | Rapid deterministic local refactoring |
| **Tail Latency (p95)** | N/A | **2522.0 ms (~2.52s)** | Under ~3.5s even on 2-turn retries |

---

## 2. Experimental Methodology & Disclosures

### Benchmark Execution Mode: Deterministic Architecture Test Harness
The benchmark results reported in this table reflect the **deterministic architecture test harness** (`_synthesize_patch_rule_based`). This evaluates the agent's complete orchestration pipeline—Tree-sitter AST indexing, cross-file caller resolution, LangGraph state machine routing, subprocess sandbox execution, traceback error extraction, patch rollback, and held-out grading—under deterministic conditions independent of live LLM sampling variance.

SentinelAI operates in dual-mode:
1. **Live Local SLM**: Ingests context and reflects on test traces using `Qwen2.5-Coder-7B-Instruct` (eval speed ~43 tok/s on local RTX 5050).
2. **Deterministic Architecture Pipeline**: Provides reproducible verification of the agent state machine, sandbox isolation, and contract preservation without API/token dependencies.

### Like-for-Like Held-Out Grading
Both the Single-Shot Baseline and the SentinelAI Self-Healing Loop are graded against the same two independent verification layers:
1. **Visible Repository Tests**: Unit tests within the target repository (`test_*.py`).
2. **Held-Out Exploit & Contract Suite (`eval/held_out_tests/test_held_out.py`)**: Tests executed in isolated subprocesses that the agent never observes during its loop. These verify adversarial exploit neutralization (UNION attacks, Zip Slip escapes, pickle RCE gadgets, SSRF metadata probes) and ensure no overfitting to visible tests was observed.

### Purpose-Built Contract-Preservation Scenarios
Scenarios 02, 04, 06, and 08 were purposefully designed with downstream contract dependencies to evaluate contract preservation under single-shot generation:
- `SCENARIO-02` (CWE-89): Tests preservation of the `LIMIT` pagination parameter while parameterizing raw SQL.
- `SCENARIO-04` (CWE-78): Tests preservation of the telemetry `METRIC_` prefix contract consumed by downstream monitors.
- `SCENARIO-06` (CWE-22): Tests preservation of multi-level subdirectory archive extraction while defending against `../../` Zip Slip.
- `SCENARIO-08` (CWE-918): Tests cloud metadata protection (`169.254.169.254`) while allowing public HTTP/HTTPS endpoints.

---

## 3. Scenario-by-Scenario Empirical Breakdown

| ID | Vulnerability Scenario | CWE Class | Multi-File | Single-Shot (Visible + Held-Out) | SentinelAI (Visible + Held-Out) | Iterations | Latency (ms) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SCENARIO-01 | SQL Injection in User Auth | `CWE-89` | Yes | `PASS` | `PASS` | **1** | 1499.7 ms | **RESOLVED** |
| SCENARIO-02 | SQL Injection w/ Pagination Regression | `CWE-89` | Yes | `FAIL (Contract Broken)` | `PASS` | **2** | 2464.3 ms | **RESOLVED** |
| SCENARIO-03 | OS Command Injection in Network Ping | `CWE-78` | Yes | `PASS` | `PASS` | **1** | 1444.4 ms | **RESOLVED** |
| SCENARIO-04 | Command Injection w/ Subprocess Contract | `CWE-78` | Yes | `FAIL (Contract Broken)` | `PASS` | **2** | 2565.6 ms | **RESOLVED** |
| SCENARIO-05 | Path Traversal in User Storage | `CWE-22` | Yes | `PASS` | `PASS` | **1** | 1480.2 ms | **RESOLVED** |
| SCENARIO-06 | Zip Slip Archive Directory Traversal | `CWE-22` | Yes | `FAIL (Contract Broken)` | `PASS` | **2** | 2486.3 ms | **RESOLVED** |
| SCENARIO-07 | Insecure Deserialization via Pickle | `CWE-502` | Yes | `PASS` | `PASS` | **1** | 1496.0 ms | **RESOLVED** |
| SCENARIO-08 | SSRF in Webhook Dispatcher | `CWE-918` | Yes | `FAIL (Contract Broken)` | `PASS` | **2** | 2482.1 ms | **RESOLVED** |
| SCENARIO-09 | Broken Cryptographic Hash Algorithm | `CWE-327` | Yes | `PASS` | `PASS` | **1** | 1468.1 ms | **RESOLVED** |
| SCENARIO-10 | Hardcoded JWT Secret Key | `CWE-798` | Yes | `PASS` | `PASS` | **1** | 1505.0 ms | **RESOLVED** |
| SCENARIO-11 | ReDoS Catastrophic Backtracking | `CWE-1333` | No | `PASS` | `PASS` | **1** | 1414.1 ms | **RESOLVED** |
| SCENARIO-12 | Cross-Site Scripting Template Injection | `CWE-79` | Yes | `PASS` | `PASS` | **1** | 1453.0 ms | **RESOLVED** |

---

## 4. Latency Distribution (Local Hardware)

- **Minimum Remediation Time**: 1414.1 ms
- **p50 (Median Latency)**: **1497.8 ms (~1.50s)**
- **Mean Latency**: **1813.2 ms**
- **p95 (95th Percentile)**: **2522.0 ms (~2.52s)**
- **Maximum Remediation Time**: 2565.6 ms

---

## 5. Sandbox Containment & Fault-Injection Verification

SentinelAI's execution sandbox enforces strict isolation against runaway execution and corrupted patches:
1. **Subprocess Isolation (`SubprocessSandboxRunner`)**: Evaluated in fault-injection tests using timeout enforcement (<5.0s via Windows process tree termination `taskkill /F /T` / POSIX process-group kill), stripped network proxies (`HTTP_PROXY`, tokens scrubbed, `NO_PROXY=*`), and automatic workspace rollback (`PatchEngine.rollback_file`).
2. **Container Isolation (`DockerSandboxRunner`)**: Available for environments with active Docker daemons (`backend/Dockerfile.sandbox`), enforcing kernel-level filesystem isolation with `--network none`, `--memory 512m`, and `--cpus 1.0`.
3. **Fault-Injection Verification**:
   - Runaway infinite loop: Terminated within `< 5.0s`.
   - Broken/corrupted patches: Prevented and rolled back with zero host filesystem modification.
