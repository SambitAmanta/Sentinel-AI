"""Unit tests for ChromaDB Local Vector RAG."""
import pytest
from app.rag.vector_store import CWEVectorStore
from app.rag.knowledge_base import CWE_KNOWLEDGE_DOCS

def test_knowledge_base_integrity():
    assert len(CWE_KNOWLEDGE_DOCS) >= 9
    for doc in CWE_KNOWLEDGE_DOCS:
        assert "cwe_id" in doc
        assert "text" in doc
        assert "title" in doc
        assert "metadata" in doc

def test_vector_store_initialization_and_query():
    store = CWEVectorStore()
    assert store.collection is not None
    assert store.collection.count() >= 9

    # Query for SQL injection guidance
    results = store.query_guidance(query="sqlite cursor execute parameter", cwe_id="CWE-89")
    assert len(results) > 0
    top_doc = results[0]
    assert "cwe_id" in top_doc["metadata"]
    assert top_doc["metadata"]["cwe_id"] == "CWE-89"
    assert "relevance_score" in top_doc

def test_vector_store_prompt_formatting():
    store = CWEVectorStore()
    results = store.query_guidance(query="command injection subprocess shlex", cwe_id="CWE-78")
    formatted = store.format_guidance_for_prompt(results)
    assert "CWE-78" in formatted
    assert "RAG Guidance" in formatted
