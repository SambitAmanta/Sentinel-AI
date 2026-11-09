import React, { useState } from 'react';
import { Header } from './components/Header';
import { VulnerabilityList } from './components/VulnerabilityList';
import { DiffViewer } from './components/DiffViewer';
import { ReasoningStream } from './components/ReasoningStream';
import { useAuditStream } from './hooks/useAuditStream';

export const App: React.FC = () => {
  const [repoPath, setRepoPath] = useState('eval/scenarios/py_sql_injection');
  const {
    status,
    logs,
    findings,
    selectedFinding,
    setSelectedFinding,
    startAudit,
  } = useAuditStream();

  const handleStart = () => {
    startAudit(repoPath);
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden select-none">
      {/* Top Application Bar */}
      <Header
        repoPath={repoPath}
        setRepoPath={setRepoPath}
        status={status}
        onStartAudit={handleStart}
      />

      {/* Main Studio Body: 3-Column Layout */}
      <main className="flex-1 grid grid-cols-12 overflow-hidden">
        {/* Left: Security Triage & Actionable Findings (3 of 12 columns) */}
        <section className="col-span-12 md:col-span-3 h-full overflow-hidden">
          <VulnerabilityList
            findings={findings}
            selectedFinding={selectedFinding}
            onSelectFinding={setSelectedFinding}
          />
        </section>

        {/* Center: Monaco Side-by-Side Diff Editor (5 of 12 columns) */}
        <section className="col-span-12 md:col-span-5 h-full overflow-hidden">
          <DiffViewer finding={selectedFinding} />
        </section>

        {/* Right: Live Agent Reasoning & Sandbox Log Stream (4 of 12 columns) */}
        <section className="col-span-12 md:col-span-4 h-full overflow-hidden border-l border-slate-800">
          <ReasoningStream logs={logs} status={status} />
        </section>
      </main>
    </div>
  );
};

export default App;
