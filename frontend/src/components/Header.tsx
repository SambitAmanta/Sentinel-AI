import React from 'react';
import { ShieldCheck, Play, Cpu, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import type { AgentStateStatus } from '../types/audit';

interface HeaderProps {
  repoPath: string;
  setRepoPath: (path: string) => void;
  status: AgentStateStatus;
  onStartAudit: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  repoPath,
  setRepoPath,
  status,
  onStartAudit,
}) => {
  const isRunning = ['STARTED', 'SCANNING', 'PLANNING', 'PATCHING', 'TESTING'].includes(status);

  const getStatusBadge = () => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> AUDIT RESOLVED
          </span>
        );
      case 'FAILED':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <AlertCircle className="w-3.5 h-3.5" /> FAILED
          </span>
        );
      case 'SCANNING':
      case 'PLANNING':
      case 'PATCHING':
      case 'TESTING':
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> {status}...
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            IDLE
          </span>
        );
    }
  };

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur sticky top-0 z-30 px-6 py-3.5">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Brand & Hardware Info */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-white tracking-tight">SentinelAI</h1>
              <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono">
                v0.1.0-local
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              Engine: <span className="text-slate-300 font-medium">RTX 5050 8GB | Qwen2.5-Coder-7B</span>
            </p>
          </div>
        </div>

        {/* Target Input & Action Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-1.5 text-sm focus-within:border-cyan-500/50 transition">
            <span className="text-xs text-slate-500 font-mono mr-2">Target:</span>
            <input
              type="text"
              value={repoPath}
              onChange={(e) => setRepoPath(e.target.value)}
              disabled={isRunning}
              className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none w-64 md:w-80"
              placeholder="eval/scenarios/py_sql_injection"
            />
          </div>

          {getStatusBadge()}

          <button
            onClick={onStartAudit}
            disabled={isRunning}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-xs tracking-wide transition shadow-lg ${
              isRunning
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold shadow-cyan-500/25 hover:shadow-cyan-500/40 active:scale-95'
            }`}
          >
            {isRunning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Auditing...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                Start Autonomous Audit
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
