# SentinelAI: Autonomous Codebase Security Audit & Refactoring Agent

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Tree-sitter](https://img.shields.io/badge/Tree--sitter-AST%20Parser-green.svg)](https://tree-sitter.github.io/tree-sitter/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> An enterprise-grade, **100% Local-First** autonomous developer agent that ingests codebases, isolates security vulnerabilities via deterministic AST and static analysis, and executes stateful self-correcting agent loops in a test sandbox to produce verified multi-file fixes and unified git diffs.

---

## 🎯 Architecture Highlights (100% Local-First & Hardware-Optimized)

Engineered specifically to run efficiently on local consumer hardware (**NVIDIA GeForce RTX 5050 8GB VRAM**) with zero external cloud dependencies, zero token cost, and complete data privacy.

* **Tree-sitter AST & Cross-File Symbol Graph**: Parses Concrete Syntax Trees (CST) and builds an in-memory symbol call graph across modules (`db.py` $\rightarrow$ `service.py`) to prevent broken function signatures or regressions.
* **Deterministic Grounding (Bandit + OWASP/CWE)**: Eliminates LLM vulnerability hallucination by using verified static analysis rulesets mapped to CWE and OWASP Top 10 standards.
* **Stateful Self-Correction Loop (LangGraph)**: An autonomous state machine (`Scan` $\rightarrow$ `Plan` $\rightarrow$ `Patch` $\rightarrow$ `Test Sandbox` $\rightarrow$ `Reflect/Heal` $\rightarrow$ `Finalize`).
* **Subprocess Sandbox Test Runner**: Executes unit test suites with strict timeout guardrails to catch regressions and inject traceback errors back into the agent context for automated healing.
* **FastAPI Streaming Engine**: Provides REST APIs and Server-Sent Events (SSE) for streaming thoughts, logs, and unified diffs.

---

## 💾 Hardware Architecture (RTX 5050 8GB VRAM Budget)

| Component | Technology | Footprint | Location |
| :--- | :--- | :--- | :--- |
| **Local Code SLM** | `Qwen2.5-Coder-7B-Instruct` (Q4_K_M) | **~4.70 GB** | GPU VRAM (Ollama) |
| **KV Cache** | 4k–8k Context Window (FlashAttention) | **~1.00 GB** | GPU VRAM |
| **Windows DWM / Display** | OS Display Buffer | **~0.90 GB** | GPU VRAM (Reserved) |
| **Tree-sitter AST Engine** | Native C Grammar Bindings | **0.00 GB** | System RAM (~150 MB) |
| **Static Security Scanner** | Bandit Engine | **0.00 GB** | System RAM (~200 MB) |
| **Total VRAM Allocated** | — | **~6.60 / 8.00 GB** | **Safe Operating Margin (~1.4 GB)** |

---

## 🚀 Quickstart

### 1. Setup Environment
```powershell
# Virtual environment is already configured in backend/.venv
.\backend\.venv\Scripts\Activate.ps1
```

### 2. Run Autonomous Security Audit via CLI
Run SentinelAI directly on our included vulnerable scenario (`eval/scenarios/py_sql_injection`):
```powershell
backend\.venv\Scripts\python.exe backend\app\cli.py --repo eval\scenarios\py_sql_injection
```

### 3. Run the Test Suite
Execute unit tests for the AST engine, LangGraph self-healing loop, and API routes:
```powershell
backend\.venv\Scripts\pytest.exe backend\tests
```

### 4. Start the FastAPI Streaming Backend
```powershell
backend\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## 📂 Repository Structure

```text
AI_Studio/
├── project_analysis.md                  # Comprehensive architectural specification
├── pyproject.toml                       # Pytest and project tooling configuration
├── README.md                            # Documentation and quickstart
│
├── backend/                             # Core Python Engine & API
│   ├── app/
│   │   ├── main.py                      # FastAPI app & SSE streaming routes
│   │   ├── cli.py                       # Rich terminal CLI runner
│   │   ├── config.py                    # Hardware & runtime configuration
│   │   ├── ast_engine/
│   │   │   ├── parser.py                # Tree-sitter AST symbol parser
│   │   │   └── symbol_graph.py          # Cross-file dependency call graph
│   │   ├── scanners/
│   │   │   ├── bandit_runner.py         # Static analyzer & CWE/OWASP mapper
│   │   │   └── schemas.py               # Pydantic vulnerability findings models
│   │   ├── agent/
│   │   │   ├── graph.py                 # LangGraph state machine workflow
│   │   │   ├── state.py                 # Pydantic agent state schema
│   │   │   └── model_client.py          # Local SLM inference client
│   │   └── sandbox/
│   │       ├── patch_engine.py          # Unified git diff generator & rollback engine
│   │       └── runner.py                # Isolated subprocess test runner
│   └── tests/                           # Integration and unit tests
│
└── eval/
    └── scenarios/
        └── py_sql_injection/            # Target scenario with vulnerable code & tests
```

---

## 🤖 Optional: Connecting Local Ollama on RTX 5050

SentinelAI includes an intelligent deterministic fallback synthesizer so it runs seamlessly out of the box without any setup. To connect a live local SLM running on your GPU:

1. Install [Ollama](https://ollama.com/) (if not already installed).
2. Pull the model:
   ```bash
   ollama pull qwen2.5-coder:7b
   ```
3. SentinelAI will automatically connect to `http://localhost:11434` and utilize GPU acceleration.

