"""Pydantic schemas for vulnerability findings and audit reports."""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    PLANNING = "PLANNING"
    PATCHING = "PATCHING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"

class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique vulnerability identifier (e.g. VULN-001)")
    check_id: str = Field(..., description="Linter or Semgrep rule ID")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration ID (e.g. CWE-89)")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category")
    severity: Severity = Field(default=Severity.HIGH)
    file_path: str = Field(..., description="Relative path to vulnerable file")
    line_start: int = Field(..., description="Starting line number (1-indexed)")
    line_end: int = Field(..., description="Ending line number (1-indexed)")
    col_start: Optional[int] = Field(None, description="Starting column")
    col_end: Optional[int] = Field(None, description="Ending column")
    message: str = Field(..., description="Description of the security vulnerability")
    code_snippet: str = Field(..., description="Original vulnerable code slice")
    suggested_fix_diff: Optional[str] = Field(None, description="Unified git diff of the proposed fix")
    status: FindingStatus = Field(default=FindingStatus.DETECTED)
    iterations_taken: int = Field(default=0, description="Self-correction cycles required to fix")
    test_stdout: Optional[str] = Field(None, description="Output from sandbox test run")

class AuditReport(BaseModel):
    repository_path: str
    total_files_scanned: int
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_duration_ms: float = 0.0

    def compute_summary(self):
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)

