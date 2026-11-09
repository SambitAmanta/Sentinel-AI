"""Pytest configuration and environment fixtures."""
import os

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["ENABLE_MOCK_LLM_FALLBACK"] = "true"

