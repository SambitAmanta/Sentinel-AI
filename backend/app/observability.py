"""OpenTelemetry Tracing and Local Telemetry Observability for SentinelAI.

Provides:
1. OpenTelemetry-compliant distributed tracing (spans, waterfalls, token metrics, tool call tracking).
2. In-memory and file-backed audit telemetry tracker for summary metrics.
"""
import contextlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. OpenTelemetry In-Memory Waterfall Exporter
# ---------------------------------------------------------------------------
class InMemoryWaterfallExporter(SpanExporter):
    """Captures OpenTelemetry spans in-memory to expose trace waterfalls for UI/API."""

    def __init__(self, max_spans: int = 200):
        self._spans: List[Dict[str, Any]] = []
        self._max_spans = max_spans

    def export(self, spans: List[ReadableSpan]) -> SpanExportResult:
        for span in spans:
            duration_ms = (span.end_time - span.start_time) / 1e6 if span.end_time and span.start_time else 0.0
            span_dict = {
                "name": span.name,
                "trace_id": format(span.context.trace_id, "032x"),
                "span_id": format(span.context.span_id, "016x"),
                "parent_span_id": format(span.parent.span_id, "016x") if span.parent else None,
                "start_time": span.start_time / 1e9 if span.start_time else time.time(),
                "end_time": span.end_time / 1e9 if span.end_time else time.time(),
                "duration_ms": round(duration_ms, 2),
                "status": span.status.status_code.name,
                "attributes": dict(span.attributes or {}),
            }
            self._spans.append(span_dict)
            if len(self._spans) > self._max_spans:
                self._spans.pop(0)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        self._spans.clear()

    def get_spans(self) -> List[Dict[str, Any]]:
        return list(self._spans)


# ---------------------------------------------------------------------------
# 2. SentinelAI OpenTelemetry Tracer
# ---------------------------------------------------------------------------
class SentinelTracer:
    """Manages OpenTelemetry tracing for agent nodes, LLM calls, tools, and sandboxes."""

    def __init__(self):
        self.exporter = InMemoryWaterfallExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        trace.set_tracer_provider(self.provider)
        self.tracer = trace.get_tracer("sentinel.ai", "1.0.0")

    @contextlib.contextmanager
    def start_span(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Context manager creating an OpenTelemetry span with auto duration and error capture."""
        with self.tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    if isinstance(v, (str, int, float, bool)):
                        span.set_attribute(k, v)
                    else:
                        span.set_attribute(k, json.dumps(v))
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, description=str(e)))
                span.record_exception(e)
                raise

    def record_llm_span(
        self,
        model: str,
        prompt_tokens: int,
        eval_tokens: int,
        eval_duration_ms: float,
        temperature: float = 0.0,
        cwe_id: Optional[str] = None
    ):
        """Records an isolated LLM inference span with standard token and latency metrics."""
        with self.tracer.start_as_current_span("sentinel.llm.inference") as span:
            span.set_attribute("gen_ai.system", "ollama")
            span.set_attribute("gen_ai.request.model", model)
            span.set_attribute("gen_ai.request.temperature", temperature)
            span.set_attribute("gen_ai.usage.input_tokens", prompt_tokens)
            span.set_attribute("gen_ai.usage.output_tokens", eval_tokens)
            span.set_attribute("sentinel.duration_ms", round(eval_duration_ms, 2))
            if cwe_id:
                span.set_attribute("security.cwe_id", cwe_id)
            span.set_status(Status(StatusCode.OK))

    def record_tool_span(self, tool_name: str, args: Dict[str, Any], result: Dict[str, Any]):
        """Records a model tool calling span."""
        with self.tracer.start_as_current_span(f"sentinel.tool.{tool_name}") as span:
            span.set_attribute("tool.name", tool_name)
            span.set_attribute("tool.arguments", json.dumps(args)[:500])
            span.set_attribute("tool.result_summary", json.dumps(result)[:500])
            is_err = result.get("error") is not None or result.get("success") is False
            span.set_status(Status(StatusCode.ERROR if is_err else StatusCode.OK))

    def record_rag_span(self, cwe_id: str, query: str, results_count: int, top_relevance: float):
        """Records a Vector RAG retrieval span."""
        with self.tracer.start_as_current_span("sentinel.rag.retrieval") as span:
            span.set_attribute("rag.cwe_id", cwe_id)
            span.set_attribute("rag.query", query[:200])
            span.set_attribute("rag.results_count", results_count)
            span.set_attribute("rag.top_relevance", round(top_relevance, 4))
            span.set_status(Status(StatusCode.OK))

    def record_sandbox_span(self, repo_path: str, passed: bool, duration_ms: float, returncode: int = 0):
        """Records a sandbox test execution span."""
        with self.tracer.start_as_current_span("sentinel.sandbox.execution") as span:
            span.set_attribute("sandbox.repo", Path(repo_path).name)
            span.set_attribute("sandbox.passed", passed)
            span.set_attribute("sandbox.returncode", returncode)
            span.set_attribute("sandbox.duration_ms", round(duration_ms, 2))
            span.set_status(Status(StatusCode.OK if passed else StatusCode.ERROR))

    def get_waterfall_traces(self) -> List[Dict[str, Any]]:
        """Returns the in-memory trace waterfall history."""
        return self.exporter.get_spans()


# ---------------------------------------------------------------------------
# 3. Telemetry Tracker (Audit Summary History)
# ---------------------------------------------------------------------------
@dataclass
class AuditTelemetryRecord:
    audit_id: str
    target_repo: str
    timestamp: float
    total_duration_ms: float
    files_scanned: int
    vulnerabilities_detected: int
    vulnerabilities_resolved: int
    iterations_taken: int
    sandbox_test_duration_ms: float
    status: str

class TelemetryTracker:
    """Records audit telemetry locally with zero cloud dependencies."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path(__file__).resolve().parent.parent / "telemetry_metrics.json"
        self._records: List[AuditTelemetryRecord] = []
        self._load_existing()

    def _load_existing(self):
        if self.storage_path.exists():
            try:
                data = json.loads(self.storage_path.read_text(encoding="utf-8"))
                for item in data:
                    self._records.append(AuditTelemetryRecord(**item))
            except Exception:
                pass

    def record_run(
        self,
        audit_id: str,
        target_repo: str,
        duration_ms: float,
        files_scanned: int,
        detected: int,
        resolved: int,
        iterations: int,
        sandbox_time_ms: float,
        status: str,
    ):
        record = AuditTelemetryRecord(
            audit_id=audit_id,
            target_repo=target_repo,
            timestamp=time.time(),
            total_duration_ms=round(duration_ms, 2),
            files_scanned=files_scanned,
            vulnerabilities_detected=detected,
            vulnerabilities_resolved=resolved,
            iterations_taken=iterations,
            sandbox_test_duration_ms=round(sandbox_time_ms, 2),
            status=status,
        )
        self._records.append(record)
        self._persist()

    def _persist(self):
        try:
            data = [asdict(r) for r in self._records]
            self.storage_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get_summary(self) -> Dict[str, Any]:
        if not self._records:
            return {
                "total_audits": 0,
                "mean_duration_ms": 0.0,
                "resolution_rate": 100.0,
                "total_vulnerabilities_fixed": 0,
            }

        total = len(self._records)
        mean_dur = sum(r.total_duration_ms for r in self._records) / total
        total_detected = sum(r.vulnerabilities_detected for r in self._records)
        total_resolved = sum(r.vulnerabilities_resolved for r in self._records)
        rate = (total_resolved / total_detected * 100) if total_detected > 0 else 100.0

        return {
            "total_audits": total,
            "mean_duration_ms": round(mean_dur, 2),
            "resolution_rate": round(rate, 1),
            "total_vulnerabilities_fixed": total_resolved,
            "records": [asdict(r) for r in self._records[-10:]],
        }

# Global Singletons
tracer = SentinelTracer()
telemetry = TelemetryTracker()
