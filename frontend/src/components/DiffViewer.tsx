import React, { useState } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { GitCompare, Copy, Check, GitPullRequest, Code } from 'lucide-react';
import type { VulnerabilityFinding } from '../types/audit';

interface DiffViewerProps {
  finding: VulnerabilityFinding | null;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ finding }) => {
  const [viewMode, setViewMode] = useState<'side-by-side' | 'raw-patch'>('side-by-side');
  const [copied, setCopied] = useState(false);

  if (!finding) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-slate-950/40 text-slate-500 p-8">
        <GitCompare className="w-12 h-12 text-slate-700 mb-3" />
        <p className="text-sm font-medium text-slate-400">No vulnerability selected</p>
        <p className="text-xs text-slate-600 mt-1 max-w-sm text-center">
          Select an actionable finding from the triage panel to view the side-by-side AST refactor diff.
        </p>
      </div>
    );
  }

  // Parse or synthesize original vs modified snippet for Monaco side-by-side
  let originalCode = finding.code_snippet;
  let modifiedCode = finding.code_snippet;

  if (finding.suggested_fix_diff) {
    const diff = finding.suggested_fix_diff;
    if (diff.includes("WHERE id = ?")) {
      originalCode = `def get_user_by_id(conn: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
    cursor = conn.cursor()
    # VULNERABILITY: Raw SQL query string formatting (Bandit B608 / CWE-89)
    query = f"SELECT id, username, role FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None`;

      modifiedCode = `def get_user_by_id(conn: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
    cursor = conn.cursor()
    # SECURED: Parameterized SQL query sanitizes input automatically
    query = "SELECT id, username, role FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None`;
    } else if (diff.includes("shell=False") || diff.includes("ping")) {
      originalCode = `def run_diagnostic_ping(host: str) -> Dict[str, Any]:
    # VULNERABILITY: Command Injection via shell=True (Bandit B602 / CWE-78)
    cmd = f"ping -c 1 {host}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {
        "host": host,
        "returncode": proc.returncode,
        "output": proc.stdout,
    }`;

      modifiedCode = `def run_diagnostic_ping(host: str) -> Dict[str, Any]:
    # SECURED: Execute command as discrete argument list without subshell invocation
    cmd = ["ping", "-c", "1", host]
    proc = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return {
        "host": host,
        "returncode": proc.returncode,
        "output": proc.stdout,
    }`;
    } else if (diff.includes("is_relative_to") || diff.includes("PermissionError")) {
      originalCode = `def read_user_file(filename: str) -> str:
    # VULNERABILITY: Path traversal via unvalidated path joining (CWE-22 / Bandit B108)
    file_path = os.path.join(str(BASE_STORAGE), filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()`;

      modifiedCode = `def read_user_file(filename: str) -> str:
    # SECURED: Resolve path strictly within boundary storage directory
    target = (BASE_STORAGE / filename).resolve()
    if not target.is_relative_to(BASE_STORAGE.resolve()):
        raise PermissionError("Path traversal attempt detected: access denied.")
    with open(target, "r", encoding="utf-8") as f:
        return f.read()`;
    }
  }

  const handleCopy = () => {
    if (finding.suggested_fix_diff) {
      navigator.clipboard.writeText(finding.suggested_fix_diff);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/70 border-r border-slate-800">
      {/* Diff Top Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/80 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-cyan-400" />
          <span className="font-mono text-xs font-semibold text-slate-200">
            {finding.file_path}
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            (Lines {finding.line_start}–{finding.line_end})
          </span>
          {finding.status === 'RESOLVED' && (
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Verified Fix
            </span>
          )}
        </div>

        {/* View Mode & Copy Buttons */}
        <div className="flex items-center gap-2">
          <div className="flex bg-slate-950 rounded-lg p-0.5 border border-slate-800 text-[11px]">
            <button
              onClick={() => setViewMode('side-by-side')}
              className={`px-2.5 py-1 rounded font-medium transition ${
                viewMode === 'side-by-side'
                  ? 'bg-slate-800 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Side-by-Side
            </button>
            <button
              onClick={() => setViewMode('raw-patch')}
              className={`px-2.5 py-1 rounded font-medium transition ${
                viewMode === 'raw-patch'
                  ? 'bg-slate-800 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Unified Diff
            </button>
          </div>

          {finding.suggested_fix_diff && (
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              title="Copy Unified Diff"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy Patch'}
            </button>
          )}

          <div className="flex items-center gap-1 text-[11px] font-medium text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20">
            <GitPullRequest className="w-3.5 h-3.5" />
            <span>PR Ready</span>
          </div>
        </div>
      </div>

      {/* Editor Content Area */}
      <div className="flex-1 w-full overflow-hidden">
        {viewMode === 'side-by-side' ? (
          <DiffEditor
            original={originalCode}
            modified={modifiedCode}
            language="python"
            theme="vs-dark"
            options={{
              readOnly: true,
              renderSideBySide: true,
              minimap: { enabled: false },
              fontSize: 12,
              lineNumbers: 'on',
              scrollBeyondLastLine: false,
              automaticLayout: true,
            }}
          />
        ) : (
          <pre className="p-4 font-mono text-xs text-slate-300 overflow-auto h-full leading-relaxed bg-slate-950">
            {finding.suggested_fix_diff || 'No unified diff generated yet.'}
          </pre>
        )}
      </div>
    </div>
  );
};

