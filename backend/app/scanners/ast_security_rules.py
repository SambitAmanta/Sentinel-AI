"""AST-based security rules using Tree-sitter to detect subtle security anti-patterns."""
import re
from pathlib import Path
from typing import List
from app.ast_engine.parser import ASTParser
from app.scanners.schemas import Severity, VulnerabilityFinding

class ASTSecurityScanner:
    """Walks the Tree-sitter CST to identify security anti-patterns across CWE classes."""

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

        # Rule 1: Path Traversal (CWE-22) in open() or zipfile.extract
        for call_node in self.parser._find_descendants(root, "call"):
            func_node = call_node.child_by_field_name("function")
            if not func_node:
                continue

            func_name = func_node.text.decode("utf-8")

            # 1a: open() with os.path.join without is_relative_to
            if func_name == "open":
                parent = call_node.parent
                while parent and parent.type not in ("function_definition", "async_function_definition"):
                    parent = parent.parent

                fn_content = content_bytes[parent.start_byte:parent.end_byte].decode("utf-8", errors="replace") if parent else ""
                if "os.path.join" in fn_content and "is_relative_to" not in fn_content:
                    findings.append(
                        VulnerabilityFinding(
                            id=f"AST-VULN-{len(findings) + 1:03d}",
                            check_id="ast.security.path-traversal",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control",
                            severity=Severity.HIGH,
                            file_path=rel_file_path,
                            line_start=call_node.start_point[0] + 1,
                            line_end=call_node.end_point[0] + 1,
                            message="Potential Path Traversal (CWE-22): File opened via os.path.join without directory boundary validation.",
                            code_snippet=fn_content.strip() or content[call_node.start_byte:call_node.end_byte],
                        )
                    )

            # 1b: Zip Slip (CWE-22)
            elif func_name.endswith("extract") or func_name.endswith("extractall"):
                call_text = content[call_node.start_byte:call_node.end_byte]
                if "is_relative_to" not in content and "resolve" not in call_text:
                    findings.append(
                        VulnerabilityFinding(
                            id=f"AST-VULN-{len(findings) + 1:03d}",
                            check_id="ast.security.zip-slip",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control",
                            severity=Severity.HIGH,
                            file_path=rel_file_path,
                            line_start=call_node.start_point[0] + 1,
                            line_end=call_node.end_point[0] + 1,
                            message="Potential Zip Slip (CWE-22): Archive member extracted without path containment verification.",
                            code_snippet=call_text,
                        )
                    )

            # Rule 2: SSRF (CWE-918)
            elif func_name.endswith("get") or func_name.endswith("post"):
                call_text = content[call_node.start_byte:call_node.end_byte]
                if "requests." in call_text and "urlparse" not in content and "169.254" not in content:
                    findings.append(
                        VulnerabilityFinding(
                            id=f"AST-VULN-{len(findings) + 1:03d}",
                            check_id="ast.security.ssrf-unvalidated-url",
                            cwe_id="CWE-918",
                            owasp_category="A10:2021-Server-Side Request Forgery",
                            severity=Severity.HIGH,
                            file_path=rel_file_path,
                            line_start=call_node.start_point[0] + 1,
                            line_end=call_node.end_point[0] + 1,
                            message="Potential SSRF (CWE-918): External HTTP request executed without hostname or IP validation.",
                            code_snippet=call_text,
                        )
                    )

            # Rule 3: Insecure eval() / exec()
            elif func_name in ("eval", "exec"):
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
                        message="Direct call to eval/exec with dynamic input detected (Code Injection).",
                        code_snippet=call_text,
                    )
                )

        # Rule 4: ReDoS (CWE-1333) - Catastrophic backtracking patterns like ([a-z]+)+
        for match in re.finditer(r'([rR]?["\']\^?(\([^\)]+\)\+)+.*["\'])', content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    id=f"AST-VULN-{len(findings) + 1:03d}",
                    check_id="ast.security.redos-backtracking",
                    cwe_id="CWE-1333",
                    owasp_category="A03:2021-Injection",
                    severity=Severity.HIGH,
                    file_path=rel_file_path,
                    line_start=line_no,
                    line_end=line_no,
                    message="Catastrophic Backtracking Regex / ReDoS (CWE-1333): Nested repetition pattern detected.",
                    code_snippet=match.group(0),
                )
            )

        # Rule 5: Reflected XSS (CWE-79) - Unescaped HTML interpolation in f-strings
        for match in re.finditer(r'f["\']<[^>]+>.*\{[a-zA-Z0-9_]+\}.*<[^>]+>["\']', content):
            line_no = content[:match.start()].count("\n") + 1
            if "escape(" not in content:
                findings.append(
                    VulnerabilityFinding(
                        id=f"AST-VULN-{len(findings) + 1:03d}",
                        check_id="ast.security.xss-html-interpolation",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        severity=Severity.HIGH,
                        file_path=rel_file_path,
                        line_start=line_no,
                        line_end=line_no,
                        message="Reflected XSS (CWE-79): Dynamic variable interpolated directly into HTML markup without escaping.",
                        code_snippet=match.group(0),
                    )
                )

        return findings
