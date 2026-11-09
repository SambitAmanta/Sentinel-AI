"""AST-based security rules using Tree-sitter to detect vulnerabilities missed by basic linters."""
from pathlib import Path
from typing import List
from app.ast_engine.parser import ASTParser
from app.scanners.schemas import Severity, VulnerabilityFinding

class ASTSecurityScanner:
    """Walks the Tree-sitter CST to identify security anti-patterns (CWE-22, CWE-95, etc.)."""

    def __init__(self, parser: ASTParser = None):
        self.parser = parser or ASTParser()

    def scan_file(self, file_path: str | Path, rel_file_path: str) -> List[VulnerabilityFinding]:
        p = Path(file_path).resolve()
        if not p.exists() or p.suffix.lower() != ".py":
            return []

        tree_parser, lang = self.parser.get_parser_for_file(p)
        if not tree_parser or lang != "python":
            return []

        try:
            content_bytes = p.read_bytes()
            content = content_bytes.decode("utf-8", errors="replace")
            tree = tree_parser.parse(content_bytes)
        except Exception:
            return []

        findings: List[VulnerabilityFinding] = []
        root = tree.root_node

        # Rule 1: Detect path traversal in open() calls with os.path.join
        for call_node in self.parser._find_descendants(root, "call"):
            func_node = call_node.child_by_field_name("function")
            if not func_node:
                continue

            func_name = func_node.text.decode("utf-8")

            if func_name == "open":
                start_line = call_node.start_point[0] + 1
                end_line = call_node.end_point[0] + 1

                # Locate enclosing function
                parent = call_node.parent
                while parent and parent.type not in ("function_definition", "async_function_definition"):
                    parent = parent.parent

                fn_content = ""
                if parent:
                    fn_content = content_bytes[parent.start_byte:parent.end_byte].decode("utf-8", errors="replace")

                # If the function uses os.path.join without is_relative_to or boundary check
                if "os.path.join" in fn_content and "is_relative_to" not in fn_content:
                    findings.append(
                        VulnerabilityFinding(
                            id=f"AST-VULN-{len(findings) + 1:03d}",
                            check_id="ast.security.path-traversal",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control",
                            severity=Severity.HIGH,
                            file_path=rel_file_path,
                            line_start=start_line,
                            line_end=end_line,
                            message="Potential Path Traversal (CWE-22): File opened via os.path.join without directory boundary validation.",
                            code_snippet=fn_content.strip() or content[call_node.start_byte:call_node.end_byte],
                        )
                    )

            # Rule 2: Insecure eval()
            elif func_name == "eval":
                call_text = content[call_node.start_byte:call_node.end_byte]
                findings.append(
                    VulnerabilityFinding(
                        id=f"AST-VULN-{len(findings) + 1:03d}",
                        check_id="ast.security.insecure-eval",
                        cwe_id="CWE-95",
                        owasp_category="A03:2021-Injection",
                        severity=Severity.CRITICAL,
                        file_path=rel_file_path,
                        line_start=call_node.start_point[0] + 1,
                        line_end=call_node.end_point[0] + 1,
                        message="Direct call to eval() with dynamic input detected (Code Injection).",
                        code_snippet=call_text,
                    )
                )

        return findings
