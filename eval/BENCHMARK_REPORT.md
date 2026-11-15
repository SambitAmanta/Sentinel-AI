# SentinelAI Empirical Benchmark Evaluation Report

**Environment**: Local Offline NVIDIA GeForce RTX 5050 (8GB VRAM)  
**Execution Timestamp**: 2026-11-15 12:43:11  
**Benchmark Target**: Single-Shot LLM Generation vs SentinelAI Autonomous Self-Healing Loop  

---

## 1. Executive Summary

| Metric | Single-Shot LLM Baseline | SentinelAI Autonomous Loop | Delta / Engineering Gain |
| :--- | :--- | :--- | :--- |
| **Pass Rate** | **66.7%** (8/12) | **100.0%** (12/12) | **+33.3% autonomous remediation gain** |
| **Test Regressions** | **33.3%** (4 regressions introduced) | **0.0%** (0 unverified diffs merged) | **100% containment of broken patches** |
| **Mean Iterations** | 1.00 (Single-shot, static) | **1.33 iterations** | **True reflection on Pytest failure traces** |
| **Median Latency (p50)**| ~145.2 ms | **1964.6 ms** | Rapid deterministic local refactoring |
| **Tail Latency (p95)** | N/A | **3458.5 ms** | Under ~4.5 seconds even on 2-turn retries |

---

## 2. Experimental Methodology

### Baseline Definition (Single-Shot Pass@1)
- **Model**: Local SLM with deterministic security prompting.
- **Protocol**: Codebase AST indexing and static vulnerability scan provide targeted finding. Model generates a patch in a single shot without sandbox execution or error feedback. The patch is applied and pytest suite runs once. If test fails or contract breaks, it is marked as a failure.
- **Why Single-Shot Fails (66.7%)**: On complex multi-file scenarios, single-shot generation produces plausible-looking security fixes that violate existing API contracts (e.g. dropping pagination parameters, blocking valid sub-paths in archive extraction, or breaking telemetry format contracts).

### SentinelAI Self-Healing Loop (Pass@3)
- **Architecture**: LangGraph state machine coordinating Tree-sitter AST symbol analysis, Bandit static scanning, and an isolated sandbox test runner.
- **Self-Healing Loop**: If a patch fails sandbox verification, SentinelAI extracts the pytest failure summary and stack trace, rolls back the failed modification to ensure a pristine working tree, and passes the error trace back to the patch synthesizer.
- **Result (100.0%)**: All 4 contract regressions introduced on Attempt 1 were self-healed on Attempt 2, achieving 100% test pass rate with 0 host regressions.

---

## 3. Scenario-by-Scenario Empirical Breakdown

| ID | Vulnerability Scenario | CWE Class | Multi-File | Baseline (Pass@1) | SentinelAI (Pass@3) | Iterations | Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SCENARIO-01 | SQL Injection in User Auth | `CWE-89` | Yes | `PASS` | `PASS` | **1** | 1737.8 ms |
| SCENARIO-02 | SQL Injection w/ Pagination Regression | `CWE-89` | Yes | `FAIL (Regression)` | `PASS` | **2** | 3203.4 ms |
| SCENARIO-03 | OS Command Injection in Network Ping | `CWE-78` | Yes | `PASS` | `PASS` | **1** | 1860.1 ms |
| SCENARIO-04 | Command Injection w/ Subprocess Contract | `CWE-78` | Yes | `FAIL (Regression)` | `PASS` | **2** | 3674.8 ms |
| SCENARIO-05 | Path Traversal in User Storage | `CWE-22` | Yes | `PASS` | `PASS` | **1** | 1729.8 ms |
| SCENARIO-06 | Zip Slip Archive Directory Traversal | `CWE-22` | Yes | `FAIL (Regression)` | `PASS` | **2** | 3262.7 ms |
| SCENARIO-07 | Insecure Deserialization via Pickle | `CWE-502` | Yes | `PASS` | `PASS` | **1** | 1840.0 ms |
| SCENARIO-08 | Server-Side Request Forgery in Webhooks | `CWE-918` | Yes | `FAIL (Regression)` | `PASS` | **2** | 3281.6 ms |
| SCENARIO-09 | Broken Cryptographic Hash Algorithm | `CWE-327` | Yes | `PASS` | `PASS` | **1** | 1725.8 ms |
| SCENARIO-10 | Hardcoded JWT Secret Key | `CWE-798` | Yes | `PASS` | `PASS` | **1** | 1690.2 ms |
| SCENARIO-11 | ReDoS Catastrophic Backtracking | `CWE-1333` | No | `PASS` | `PASS` | **1** | 2963.7 ms |
| SCENARIO-12 | Cross-Site Scripting Template Injection | `CWE-79` | Yes | `PASS` | `PASS` | **1** | 2069.1 ms |

---

## 4. Latency Distribution (Local Hardware)

- **Minimum Remediation Time**: 1690.2 ms (Single-file direct AST refactoring)
- **p50 (Median Latency)**: **1964.6 ms**
- **Mean Latency**: **2419.9 ms**
- **p95 (95th Percentile)**: **3458.5 ms**
- **Maximum Remediation Time**: 3674.8 ms (Multi-file cross-boundary self-healing)

---

## 5. Sandbox Containment & Fault-Injection Verification

In addition to security remediation, SentinelAI's sandbox was evaluated against fault-injection attacks:
1. **Runaway Process Containment**: Injected infinite `while True` loop was terminated within `< 5.0s` by Windows process tree kill (`taskkill /F /T /PID`).
2. **Host Write Escape Containment**: Attempts to write files outside the repository root were blocked and rolled back with zero host file system modification.
