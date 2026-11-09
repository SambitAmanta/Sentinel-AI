export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'DETECTED' | 'PLANNING' | 'PATCHING' | 'VERIFYING' | 'RESOLVED' | 'FAILED';

export interface VulnerabilityFinding {
  id: string;
  check_id: string;
  cwe_id: string | null;
  owasp_category: string | null;
  severity: Severity;
  file_path: string;
  line_start: number;
  line_end: number;
  col_start?: number | null;
  col_end?: number | null;
  message: string;
  code_snippet: string;
  suggested_fix_diff: string | null;
  status: FindingStatus;
  iterations_taken: number;
  test_stdout?: string | null;
}

export type AgentStateStatus = 'IDLE' | 'STARTED' | 'SCANNING' | 'PLANNING' | 'PATCHING' | 'TESTING' | 'COMPLETED' | 'FAILED';

export interface StreamEvent {
  type: string;
  message?: string;
  status?: string;
  findings?: VulnerabilityFinding[];
  diffs?: string[];
  payload?: Record<string, unknown>;
}
