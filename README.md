# SentinelAI: Autonomous Codebase Security Audit & Refactoring Agent

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Tree-sitter](https://img.shields.io/badge/Tree--sitter-AST%20Parser-green.svg)](https://tree-sitter.github.io/tree-sitter/)
[![React 19](https://img.shields.io/badge/React-19.x-61dafb.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646cff.svg)](https://vitejs.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A **100% Local-First** autonomous developer agent that ingests codebases, isolates security vulnerabilities via deterministic AST and static analysis, and executes stateful self-correcting agent loops in a test sandbox to produce verified multi-file fixes and unified git diffs.

---

## 📑 Table of Contents
- [Architecture & Design Highlights](#-architecture-highlights-100-local-first)
- [System Workflow](#-system-workflow)
- [Empirical Benchmark Results](#-empirical-evaluation-benchmark-results-rtx-5050-8gb)
- [Hardware-Aware VRAM Budget](#-hardware-architecture-rtx-5050-8gb-vram-budget)
- [Interactive Studio Dashboard](#-interactive-studio-dashboard-frontend)
- [Quickstart Guide](#-quickstart)
- [API & Telemetry Reference](#-api--telemetry-reference)
- [Repository Layout](#-repository-structure)
- [Resume Bullet Points](#-resume-bullet-points-ready-for-copy-paste)

---

## 🎯 Architecture Highlights (100% Local-First)

Engineered specifically to run efficiently on consumer/edge hardware (**NVIDIA GeForce RTX 5050 8GB VRAM**) with **zero external cloud dependencies, zero token cost, and complete data privacy**.

1. **Tree-sitter AST & Cross-File Symbol Graph**: Parses Concrete Syntax Trees (CST) and builds an in-memory symbol call graph across modules (`db.py` $\rightarrow$ `service.py`) to prevent broken function signatures or regressions.
2. **Deterministic Grounding (Bandit + AST Rules + OWASP/CWE)**: Grounds vulnerability detection in deterministic AST analysis and Bandit static rulesets mapped to CWE and OWASP Top 10 standards.
3. **Stateful Self-Correction Loop (LangGraph)**: An autonomous state machine (`Scan` $\rightarrow$ `Plan` $\rightarrow$ `Patch` $\rightarrow$ `Test Sandbox` $\rightarrow$ `Reflect/Heal` $\rightarrow$ `Finalize`).
4. **Subprocess & Container Sandbox Test Runner**: Executes unit test suites with strict timeout guardrails to catch regressions and inject traceback errors back into the agent context for automated healing.
5. **Real-Time Streaming Studio**: FastAPI Server-Sent Events (SSE) streaming thought tokens and sandbox logs directly to a modern React + Monaco Diff viewer.
6. **Local Telemetry & Observability**: In-memory and file-backed telemetry logging audit latencies, resolution rates, and sandbox runtimes without third-party cloud trackers.

---

## 🔄 System Workflow

```mermaid
flowchart TD
    Repo["Target Codebase<br/>(e.g., Python / TS Microservice)"] --> Scan["1. Ingestion & Scan<br/>Tree-sitter AST + Bandit + Custom AST Rules"]
    Scan --> Graph["2. Symbol Graph Resolution<br/>Extract Enclosing Function & Callers"]
    Graph --> State["3. LangGraph State Machine<br/>Pydantic Structured Findings"]
    
    State --> Patch["4. Patch Synthesis<br/>Local SLM (Qwen2.5-Coder) / Structured Synthesis"]
    Patch --> Sandbox["5. Sandbox Verification<br/>Execute Unit Tests in Subprocess / Docker Sandbox"]

    Sandbox -->|Regression / Test Failed| Reflect["Self-Healing Reflection<br/>Inject Traceback & Retry (Max 3)"]
    Reflect --> Patch

    Sandbox -->|Tests Passed 100%| Finalize["6. Final Verification<br/>Generate Unified Git Diff & Monaco View"]
    Finalize --> Output["Verified Patch & PR Ready"]
```

---

## 📊 Empirical Evaluation Benchmark Results (RTX 5050 8GB)

SentinelAI includes an automated evaluation benchmark (`eval/run_benchmark.py`) testing the agent across **12 distinct scenarios** and **8 CWE classes** (including 8 multi-file repositories). It evaluates **Single-Shot LLM Generation (Pass@1)** against the **SentinelAI Autonomous Self-Healing Loop (Pass@3)**:

| Scenario ID | Vulnerability Scenario | CWE Class | Multi-File | Single-Shot (Pass@1) | SentinelAI (Pass@3) | Iterations | Latency | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SCENARIO-01** | SQL Injection in User Auth | CWE-89 | Yes | `PASS` | `PASS (100%)` | 1 | 1,738 ms | **RESOLVED** |
| **SCENARIO-02** | SQL Injection w/ Pagination Regression | CWE-89 | Yes | `FAIL (0%)` | `PASS (100%)` | 2 | 3,203 ms | **RESOLVED** |
| **SCENARIO-03** | OS Command Injection in Network Ping | CWE-78 | Yes | `PASS` | `PASS (100%)` | 1 | 1,860 ms | **RESOLVED** |
| **SCENARIO-04** | Command Injection w/ Subprocess Contract | CWE-78 | Yes | `FAIL (0%)` | `PASS (100%)` | 2 | 3,675 ms | **RESOLVED** |
| **SCENARIO-05** | Path Traversal in User Storage | CWE-22 | Yes | `PASS` | `PASS (100%)` | 1 | 1,730 ms | **RESOLVED** |
| **SCENARIO-06** | Zip Slip Archive Directory Traversal | CWE-22 | Yes | `FAIL (0%)` | `PASS (100%)` | 2 | 3,263 ms | **RESOLVED** |
| **SCENARIO-07** | Insecure Deserialization via Pickle | CWE-502 | Yes | `PASS` | `PASS (100%)` | 1 | 1,840 ms | **RESOLVED** |
| **SCENARIO-08** | SSRF in Webhook Dispatcher | CWE-918 | Yes | `FAIL (0%)` | `PASS (100%)` | 2 | 3,282 ms | **RESOLVED** |
| **SCENARIO-09** | Broken Cryptographic Hash (MD5) | CWE-327 | Yes | `PASS` | `PASS (100%)` | 1 | 1,726 ms | **RESOLVED** |
| **SCENARIO-10** | Hardcoded JWT Secret Key | CWE-798 | Yes | `PASS` | `PASS (100%)` | 1 | 1,690 ms | **RESOLVED** |
| **SCENARIO-11** | ReDoS Catastrophic Backtracking | CWE-1333 | No | `PASS` | `PASS (100%)` | 1 | 2,964 ms | **RESOLVED** |
| **SCENARIO-12** | Cross-Site Scripting HTML Injection | CWE-79 | Yes | `PASS` | `PASS (100%)` | 1 | 2,069 ms | **RESOLVED** |

### Benchmark Analysis & Findings
* **Single-Shot Baseline (Pass@1)**: **`66.7%`** (8/12). While single-shot generation resolves isolated functions, it introduces breaking contract regressions in 33.3% of cases (e.g., dropping pagination parameters, breaking telemetry format contracts, or rejecting valid nested archive paths).
* **SentinelAI Autonomous Loop (Pass@3)**: **`100.0%`** (12/12) with **`0.0%` test regressions**. All 4 contract regressions introduced on Attempt 1 were self-healed on Attempt 2 via traceback reflection.
* **Mean Self-Healing Iterations**: **`1.33` iterations/scenario** (demonstrating genuine multi-turn reflection on test failure traces).
* **Deterministic Containment**: 2 fault-injection test cases (runaway infinite loops and host write escapes) were contained with zero host impact.
* **Latency Profile**: **Median (p50): ~1.96s** | **Mean: ~2.42s** | **Tail (p95): ~3.46s** running locally on an RTX 5050 8GB.

---

## 💾 Hardware Architecture (RTX 5050 8GB VRAM Budget)

To ensure zero Out-Of-Memory (OOM) errors and sub-second token generation on an 8GB GPU, memory is strictly partitioned:

| Component | Technology | Footprint | Location |
| :--- | :--- | :--- | :--- |
| **Local Code SLM** | `Qwen2.5-Coder-7B-Instruct` (Q4_K_M) | **~4.70 GB** | GPU VRAM (Ollama) |
| **KV Cache** | 4k–8k Context Window (FlashAttention) | **~1.00 GB** | GPU VRAM |
| **Windows DWM / Display** | OS Display Buffer | **~0.90 GB** | GPU VRAM (Reserved) |
| **Tree-sitter AST Engine** | Native C Grammar Bindings | **0.00 GB** | System RAM (~150 MB) |
| **Static Security Scanner** | Bandit Engine | **0.00 GB** | System RAM (~200 MB) |
| **Total VRAM Allocated** | — | **~6.60 / 8.00 GB** | **Safe Operating Margin (~1.4 GB)** |

---

## 🖥️ Interactive Studio Dashboard (Frontend)

The frontend is an interactive developer studio built with **Vite, React 19, TypeScript, and Tailwind CSS**:

```
┌────────────────────────────────────────────────────────────────────────┐
│  🛡️ SentinelAI Studio     [ Target: Preset Dropdown ▼ ]  │ [ Start Audit ]
├─────────────────┬──────────────────────────────────┬───────────────────┤
│  VULNERABILITY  │        MONACO DIFF VIEWER        │  REAL-TIME AGENT  │
│  TRIAGE LIST    │   Original   vs   Refactored     │  REASONING STREAM │
├─────────────────┼──────────────────────────────────┼───────────────────┤
│ [VULN-001]      │ 22 # Vulnerable:                 │ 🔍 AST Ingesting  │
│ CWE-89 SQL Inj  │- query = f"SELECT...             │ 🌲 Tree-sitter    │
│ Severity: HIGH  │+ query = "SELECT... ?"           │ 🎯 Finding B608   │
│ Status: RESOLVED│+ cursor.execute(query, (id,))    │ ✍️ Patching...    │
│                 │                                  │ 🧪 Sandbox PASS   │
│ Metrics:        │ Controls:                        │                   │
│ • 1 Actionable  │ • Side-by-Side vs Unified Diff   │ LangGraph State:  │
│ • 1 Auto-Fixed  │ • Copy Patch & PR Ready Badges   │ [COMPLETED]       │
└─────────────────┴──────────────────────────────────┴───────────────────┘
```

* **Header Controls**: Quick scenario preset switcher (`SQL Injection`, `Command Injection`, `Path Traversal`), GPU hardware status badge, and audit execution button.
* **Triage Panel**: Real-time summary metrics, severity badges (`CRITICAL`, `HIGH`), and CWE mapping.
* **Monaco Diff Editor**: Side-by-side syntax-highlighted editor showing deleted lines in red and parameterized secure code in green.
* **Live Reasoning Stream**: Terminal-style drawer streaming node transitions, thought tokens, and sandbox test execution times.

---

## 🚀 Quickstart

### 1. Setup Environment
```powershell
# Virtual environment is already configured in backend/.venv
.\backend\.venv\Scripts\Activate.ps1
```

### 2. Run Autonomous Security Audit via CLI
Run SentinelAI directly on any vulnerable scenario:
```powershell
backend\.venv\Scripts\python.exe backend\app\cli.py --repo eval\scenarios\py_sql_injection
```

### 3. Run the Automated Benchmark Suite
Evaluate Pass@1 baseline vs Pass@3 self-healing loop across all scenarios:
```powershell
backend\.venv\Scripts\python.exe eval\run_benchmark.py
```

### 4. Run the Backend Test Suite
Execute unit tests for the AST engine, LangGraph self-healing loop, API routes, and telemetry:
```powershell
backend\.venv\Scripts\pytest.exe backend\tests
```

### 5. Start the FastAPI Streaming Backend
```powershell
backend\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
API Documentation available at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

### 6. Start the Interactive Dashboard (Frontend)
In a new terminal window:
```powershell
cd frontend
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 📡 API & Telemetry Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/audit/start` | Initiates an autonomous audit for `repository_path`. Returns `session_id`. |
| `GET` | `/api/audit/stream/{session_id}` | Server-Sent Events (SSE) streaming thought tokens, logs, and unified diffs. |
| `GET` | `/api/audit/status/{session_id}` | Retrieves the current state, findings, and applied diffs for a session. |
| `GET` | `/api/telemetry/metrics` | Returns aggregated metrics: total audits, mean duration, and fix rate. |
| `GET` | `/api/health` | Health-check endpoint reporting app version and local model configuration. |

---

## 📂 Repository Structure

```text
AI_Studio/
├── project_analysis.md                  # Comprehensive architectural specification
├── pyproject.toml                       # Pytest and project tooling configuration
├── README.md                            # Complete documentation & quickstart
│
├── backend/                             # Core Python Engine & API
│   ├── app/
│   │   ├── main.py                      # FastAPI app & SSE streaming routes
│   │   ├── cli.py                       # Rich terminal CLI runner
│   │   ├── config.py                    # Hardware & runtime configuration
│   │   ├── observability.py             # Telemetry & metrics tracker
│   │   │
│   │   ├── ast_engine/                  # Pillar 1: AST Ingestion
│   │   │   ├── parser.py                # Tree-sitter CST parser (Python, JS, TS)
│   │   │   └── symbol_graph.py          # Cross-file dependency call graph
│   │   │
│   │   ├── scanners/                    # Pillar 2: Static Analysis
│   │   │   ├── bandit_runner.py         # Bandit scanner & CWE/OWASP mapper
│   │   │   ├── ast_security_rules.py    # Custom Tree-sitter AST security rules
│   │   │   └── schemas.py               # Pydantic vulnerability findings models
│   │   │
│   │   ├── agent/                       # Pillar 3: LangGraph State Machine
│   │   │   ├── graph.py                 # LangGraph state machine workflow
│   │   │   ├── state.py                 # Pydantic agent state schema
│   │   │   └── model_client.py          # Local SLM inference client
│   │   │
│   │   └── sandbox/                     # Pillar 4: Execution Sandbox
│   │       ├── patch_engine.py          # Unified git diff generator & rollback engine
│   │       └── runner.py                # Isolated subprocess test runner
│   │
│   └── tests/                           # Unit and integration test suites (5 test suites)
│       ├── test_agent_loop.py           # LangGraph self-healing loop tests
│       ├── test_api_direct.py           # FastAPI route handler direct tests
│       ├── test_ast_engine.py           # Tree-sitter symbol graph & caller tests
│       ├── test_sandbox_fault_injection.py # Infinite loop & host write escape containment
│       └── test_telemetry.py            # Audit metrics tracking tests
│
├── frontend/                            # Pillar 5: Interactive Developer Studio
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.tsx               # Control bar & scenario preset selector
│   │   │   ├── VulnerabilityList.tsx    # Triage list & severity cards
│   │   │   ├── DiffViewer.tsx           # Monaco side-by-side diff viewer
│   │   │   └── ReasoningStream.tsx      # Terminal SSE reasoning stream
│   │   ├── hooks/
│   │   │   └── useAuditStream.ts        # SSE event stream connection hook
│   │   ├── types/
│   │   │   └── audit.ts                 # TypeScript type definitions
│   │   ├── App.tsx                      # 3-column studio layout
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
└── eval/                                # Benchmark Suite & Telemetry
    ├── scenarios/                       # 12 benchmark scenarios across 8 CWE classes
    │   ├── py_sql_injection/            # CWE-89 SQL Injection target
    │   ├── py_sql_multikey_regression/  # CWE-89 Multi-file & pagination contract
    │   ├── py_command_injection/        # CWE-78 Command Injection target
    │   ├── py_cmd_injection_multiturn/  # CWE-78 Multi-file & telemetry format contract
    │   ├── py_path_traversal/           # CWE-22 Path Traversal target
    │   ├── py_path_traversal_zip/       # CWE-22 Zip Slip archive traversal
    │   ├── py_insecure_deserialization/ # CWE-502 Pickle deserialization target
    │   ├── py_ssrf_webhook/             # CWE-918 SSRF cloud metadata protection
    │   ├── py_weak_crypto_md5/          # CWE-327 Obsolete MD5 hash upgrade
    │   ├── py_hardcoded_secrets/        # CWE-798 Hardcoded JWT secret migration
    │   ├── py_redos_email/              # CWE-1333 ReDoS regex backtracking
    │   └── py_xss_template/             # CWE-79 Stored XSS template escaping
    ├── run_benchmark.py                 # Automated benchmark evaluator
    └── BENCHMARK_REPORT.md              # Empirical evaluation report
```

---

## 💼 Resume Bullet Points (Ready for Copy-Paste)

* Automated verified security patches across 12 vulnerability scenarios and 8 CWE classes at 100% pass rate with zero test regressions (vs. 66.7% single-shot baseline), utilizing autonomous error reflection and code rollback to self-heal contract breakages.
* Contained runaway execution and out-of-scope file modifications with zero host impact inside a timeout-enforced test sandbox, streaming live diffs and reasoning traces to an interactive dashboard at ~1.9s median remediation.
* Technologies: LangGraph, Tree-sitter (AST), Pytest Sandbox.
