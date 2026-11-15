"""Sandbox Patch Engine for applying, validating, and rolling back code patches."""
import difflib
import logging
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class PatchEngine:
    """Safely applies code modifications, produces unified diffs, and provides rollback capabilities."""

    def __init__(self):
        # file_path -> original_content
        self._backup_store: Dict[str, str] = {}

    def backup_file(self, file_path: str | Path) -> None:
        p = Path(file_path).resolve()
        if p.exists() and str(p) not in self._backup_store:
            self._backup_store[str(p)] = p.read_text(encoding="utf-8")

    def rollback_all(self) -> None:
        """Restores all modified files to their original state."""
        for path_str, original_content in self._backup_store.items():
            Path(path_str).write_text(original_content, encoding="utf-8")
        self._backup_store.clear()

    def rollback_file(self, file_path: str | Path) -> bool:
        p = Path(file_path).resolve()
        if str(p) in self._backup_store:
            p.write_text(self._backup_store[str(p)], encoding="utf-8")
            del self._backup_store[str(p)]
            return True
        return False

    def generate_diff(self, original_text: str, modified_text: str, filename: str = "target_file") -> str:
        """Produces a standard Git-compatible unified diff."""
        original_lines = original_text.splitlines(keepends=True)
        modified_lines = modified_text.splitlines(keepends=True)
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            n=3,
        )
        return "".join(diff)

    def _inject_missing_imports(self, content: str, replacement: str) -> str:
        """Generic standard-library import resolver that detects referenced stdlib modules and functions."""
        to_inject = []

        # 1. Generic resolution for any module in Python's standard library (e.g. json, html, os, re, hashlib, etc.)
        stdlib_names = getattr(sys, "stdlib_module_names", set())
        module_refs = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\.[a-zA-Z0-9_]+", replacement))
        for mod in sorted(module_refs):
            if mod in stdlib_names:
                if not re.search(rf"^\s*(?:import\s+{mod}\b|from\s+{mod}\b)", content, re.MULTILINE):
                    to_inject.append(f"import {mod}")

        # 2. Standalone stdlib utility functions often called bare
        known_functions = {
            r"\bescape\(": "from html import escape",
            r"\burlparse\(": "from urllib.parse import urlparse",
        }
        for pattern, imp in known_functions.items():
            if re.search(pattern, replacement):
                mod = imp.split()[1]
                if not re.search(rf"^\s*(?:import\s+{mod}\b|from\s+{mod}\b)", content, re.MULTILINE) and f"import {mod}" not in to_inject:
                    to_inject.append(imp)

        if to_inject:
            doc_match = re.match(r'^(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')\s*\n', content)
            insert_pos = doc_match.end() if doc_match else 0
            injection_str = "\n".join(to_inject) + "\n"
            return content[:insert_pos] + injection_str + content[insert_pos:]
        return content

    def apply_replacement(self, file_path: str | Path, target_snippet: str, replacement_snippet: str) -> Tuple[bool, str]:
        """Replaces target_snippet with replacement_snippet in file_path with automatic backup."""
        p = Path(file_path).resolve()
        if not p.exists():
            return False, f"File not found: {p}"

        self.backup_file(p)
        content = p.read_text(encoding="utf-8")

        # Normalize line endings
        content_norm = content.replace("\r\n", "\n")
        target_norm = target_snippet.replace("\r\n", "\n")
        replacement_norm = replacement_snippet.replace("\r\n", "\n")

        if target_norm not in content_norm:
            target_norm_strip = target_snippet.strip().replace("\r\n", "\n")
            if target_norm_strip in content_norm:
                target_norm = target_norm_strip
                replacement_norm = replacement_snippet.strip().replace("\r\n", "\n")
            else:
                return False, "Target snippet not found in file."

        # Check for multi-line execute subsumption
        if "cursor.execute(" in replacement_norm:
            pos = content_norm.find(target_norm)
            if pos != -1:
                after = content_norm[pos + len(target_norm):]
                m = re.match(r"^\s*\n\s*cursor\.execute\([^\)]*\)", after)
                if m:
                    target_norm = target_norm + m.group(0)

        new_content = content_norm.replace(target_norm, replacement_norm, 1)
        new_content = self._inject_missing_imports(new_content, replacement_norm)
        p.write_text(new_content, encoding="utf-8")

        diff = self.generate_diff(content_norm, new_content, filename=p.name)
        return True, diff

