"""Unit tests for OpenTelemetry distributed tracing."""
from app.observability import tracer

def test_opentelemetry_custom_spans():
    with tracer.start_span("test.operation", {"user.id": "test_dev", "batch_size": 10}) as span:
        assert span is not None

    spans = tracer.get_waterfall_traces()
    matching = [s for s in spans if s["name"] == "test.operation"]
    assert len(matching) > 0
    s = matching[-1]
    assert s["status"] == "OK"
    assert s["attributes"].get("user.id") == "test_dev"
    assert s["duration_ms"] >= 0.0

def test_opentelemetry_semantic_spans():
    tracer.record_llm_span(
        model="qwen2.5-coder:7b",
        prompt_tokens=50,
        eval_tokens=100,
        eval_duration_ms=1200.0,
        temperature=0.0,
        cwe_id="CWE-89"
    )
    tracer.record_tool_span(
        tool_name="get_symbol_callers",
        args={"file": "test.py"},
        result={"callers": ["main"]}
    )
    tracer.record_rag_span(
        cwe_id="CWE-89",
        query="sqlite cursor",
        results_count=2,
        top_relevance=0.88
    )

    spans = tracer.get_waterfall_traces()
    names = [s["name"] for s in spans]
    assert "sentinel.llm.inference" in names
    assert "sentinel.tool.get_symbol_callers" in names
    assert "sentinel.rag.retrieval" in names
