import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, Sparkles } from 'lucide-react';
import type { AgentStateStatus } from '../types/audit';

interface ReasoningStreamProps {
  logs: string[];
  status: AgentStateStatus;
}

export const ReasoningStream: React.FC<ReasoningStreamProps> = ({ logs, status }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="flex flex-col h-full bg-slate-950 font-mono text-xs">
      {/* Drawer Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2 text-slate-300">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold text-xs tracking-wide">Live Agent Trace &amp; Sandbox Log</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[11px] text-slate-400">SSE Active</span>
        </div>
      </div>

      {/* Terminal Log Output */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2 select-text">
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-600 text-center py-10">
            <Sparkles className="w-6 h-6 mb-2 opacity-50" />
            <p>Ready to trace LangGraph autonomous loop.</p>
            <p className="text-[11px] mt-1 text-slate-700">Logs and thought tokens will stream here via SSE.</p>
          </div>
        ) : (
          logs.map((log, index) => {
            const isSuccess = log.includes('✅') || log.includes('PASSED');
            const isError = log.includes('❌') || log.includes('FAILED') || log.includes('⚠️');
            const isFinding = log.includes('🎯') || log.includes('🛡️');
            const isPatch = log.includes('✍️') || log.includes('✨');

            return (
              <div
                key={index}
                className={`flex items-start gap-2.5 leading-relaxed transition-all ${
                  isSuccess
                    ? 'text-emerald-400 bg-emerald-950/20 px-2 py-1 rounded border-l-2 border-emerald-500'
                    : isError
                    ? 'text-rose-400 bg-rose-950/20 px-2 py-1 rounded border-l-2 border-rose-500'
                    : isFinding
                    ? 'text-amber-300'
                    : isPatch
                    ? 'text-cyan-300'
                    : 'text-slate-300'
                }`}
              >
                <span className="text-slate-600 select-none text-[10px] pt-0.5">
                  {(index + 1).toString().padStart(2, '0')}
                </span>
                <span className="flex-1 break-words">{log}</span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>

      {/* Bottom Status Ticker */}
      <div className="px-4 py-2 bg-slate-900/60 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
        <span className="flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          LangGraph State: <span className="font-semibold text-slate-200">{status}</span>
        </span>
        <span className="text-slate-500 font-mono">Subprocess Sandbox: Armed</span>
      </div>
    </div>
  );
};
