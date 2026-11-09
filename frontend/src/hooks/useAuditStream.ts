import { useState, useCallback, useRef, useEffect } from 'react';
import type { VulnerabilityFinding, AgentStateStatus, StreamEvent } from '../types/audit';

export function useAuditStream() {
  const [status, setStatus] = useState<AgentStateStatus>('IDLE');
  const [logs, setLogs] = useState<string[]>([]);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [diffs, setDiffs] = useState<string[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  const startAudit = useCallback(async (repoPath: string) => {
    // Reset state
    setStatus('STARTED');
    setLogs([`🚀 Initializing audit session for target: ${repoPath}...`]);
    setFindings([]);
    setDiffs([]);
    setSelectedFinding(null);
    setError(null);

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      const res = await fetch('/api/audit/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository_path: repoPath }),
      });

      if (!res.ok) {
        throw new Error(`Failed to start audit: ${res.statusText}`);
      }

      const data = await res.json();
      const newSessionId = data.session_id;
      setSessionId(newSessionId);
      setStatus('SCANNING');

      // Connect EventSource to stream
      const es = new EventSource(`/api/audit/stream/${newSessionId}`);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const payload: StreamEvent = JSON.parse(event.data);
          handleStreamPayload(payload);
        } catch {
          // ignore non-json keepalive
        }
      };

      // Custom event listeners matching FastAPI SSE event types
      es.addEventListener('log', (event: MessageEvent) => {
        try {
          const payload: StreamEvent = JSON.parse(event.data);
          if (payload.message) {
            setLogs((prev) => [...prev, payload.message!]);
          }
        } catch {
          // fallback
        }
      });

      es.addEventListener('status_change', (event: MessageEvent) => {
        try {
          const payload: StreamEvent = JSON.parse(event.data);
          if (payload.status) {
            setStatus(payload.status as AgentStateStatus);
          }
          if (payload.message) {
            setLogs((prev) => [...prev, payload.message!]);
          }
        } catch {
          // fallback
        }
      });

      es.addEventListener('completed', (event: MessageEvent) => {
        try {
          const payload: StreamEvent = JSON.parse(event.data);
          setStatus('COMPLETED');
          if (payload.findings) {
            setFindings(payload.findings);
            if (payload.findings.length > 0) {
              setSelectedFinding(payload.findings[0]);
            }
          }
          if (payload.diffs) {
            setDiffs(payload.diffs);
          }
          es.close();
        } catch {
          // fallback
        }
      });

      es.addEventListener('error', (event) => {
        console.error('SSE Error:', event);
        es.close();
      });

    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error starting audit';
      setError(msg);
      setStatus('FAILED');
      setLogs((prev) => [...prev, `❌ Error: ${msg}`]);
    }
  }, []);

  const handleStreamPayload = (payload: StreamEvent) => {
    if (payload.type === 'log' && payload.message) {
      setLogs((prev) => [...prev, payload.message!]);
    } else if (payload.type === 'completed') {
      setStatus('COMPLETED');
      if (payload.findings) {
        setFindings(payload.findings);
        if (payload.findings.length > 0) {
          setSelectedFinding(payload.findings[0]);
        }
      }
      if (payload.diffs) {
        setDiffs(payload.diffs);
      }
      eventSourceRef.current?.close();
    }
  };

  useEffect(() => {
    return () => {
      eventSourceRef.current?.close();
    };
  }, []);

  return {
    status,
    logs,
    findings,
    diffs,
    selectedFinding,
    setSelectedFinding,
    sessionId,
    error,
    startAudit,
  };
}

