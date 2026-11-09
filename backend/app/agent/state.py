"""State schema for the LangGraph agent loop."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from app.scanners.schemas import VulnerabilityFinding

class AgentState(BaseModel):
    repository_path: str
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    current_finding_index: int = 0
    iteration: int = 0
    max_iterations: int = 3
    applied_diffs: List[str] = Field(default_factory=list)
    last_test_error: Optional[str] = None
    status: str = "IDLE"
    logs: List[str] = Field(default_factory=list)

    def current_finding(self) -> Optional[VulnerabilityFinding]:
        if 0 <= self.current_finding_index < len(self.findings):
            return self.findings[self.current_finding_index]
        return None

    def add_log(self, message: str):
        self.logs.append(message)

