"""Cross-file Symbol Graph Indexer for tracking functions, classes, and call hierarchies."""
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from app.ast_engine.parser import ASTParser, CodeSymbol

class SymbolGraph:
    """Builds and maintains an in-memory cross-file dependency graph of code symbols."""

    def __init__(self, parser: Optional[ASTParser] = None):
        self.parser = parser or ASTParser()
        self.symbols_by_name: Dict[str, List[CodeSymbol]] = defaultdict(list)
        self.symbols_by_file: Dict[str, List[CodeSymbol]] = defaultdict(list)
        # callee -> callers
        self.callers_map: Dict[str, Set[str]] = defaultdict(set)
        # caller -> callees
        self.callees_map: Dict[str, Set[str]] = defaultdict(set)

    def index_directory(self, root_dir: str | Path, recursive: bool = True) -> int:
        """Parses all supported source files in root_dir and populates the symbol graph."""
        root = Path(root_dir).resolve()
        if not root.exists():
            return 0

        self.symbols_by_name.clear()
        self.symbols_by_file.clear()
        self.callers_map.clear()
        self.callees_map.clear()

        pattern = "**/*" if recursive else "*"
        total_files = 0

        for file_path in root.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in self.parser.SUPPORTED_EXTENSIONS:
                # Skip venv, git, node_modules, tests
                parts = file_path.parts
                if any(ignored in parts for ignored in (".venv", "node_modules", ".git", "__pycache__")):
                    continue

                symbols = self.parser.parse_file(file_path)
                rel_path = str(file_path.relative_to(root))

                for sym in symbols:
                    sym.file_path = rel_path
                    self.symbols_by_name[sym.name].append(sym)
                    self.symbols_by_file[rel_path].append(sym)

                    # Build call links
                    for called_fn in sym.calls:
                        self.callees_map[sym.name].add(called_fn)
                        self.callers_map[called_fn].add(sym.name)

                total_files += 1

        return total_files

    def get_symbol(self, name: str, file_path: Optional[str] = None) -> Optional[CodeSymbol]:
        candidates = self.symbols_by_name.get(name, [])
        if not candidates:
            return None
        if file_path:
            for c in candidates:
                if c.file_path == file_path:
                    return c
        return candidates[0]

    def get_symbol_at_line(self, file_path: str, line_number: int) -> Optional[CodeSymbol]:
        """Finds the function or class enclosing a specific line number."""
        file_symbols = self.symbols_by_file.get(file_path, [])
        enclosing = None
        smallest_span = float("inf")

        for sym in file_symbols:
            if sym.line_start <= line_number <= sym.line_end:
                span = sym.line_end - sym.line_start
                if span < smallest_span:
                    smallest_span = span
                    enclosing = sym

        return enclosing

    def get_callers(self, symbol_name: str) -> List[CodeSymbol]:
        """Returns all functions that invoke the given symbol."""
        caller_names = self.callers_map.get(symbol_name, set())
        caller_symbols = []
        for name in caller_names:
            caller_symbols.extend(self.symbols_by_name.get(name, []))
        return caller_symbols

    def get_context_for_vulnerability(self, file_path: str, line_number: int) -> Dict[str, Any]:
        """Generates focused AST context for a vulnerability finding."""
        enclosing_symbol = self.get_symbol_at_line(file_path, line_number)
        callers = []

        if enclosing_symbol:
            callers = self.get_callers(enclosing_symbol.name)

        return {
            "enclosing_symbol": enclosing_symbol,
            "callers": callers,
            "file_symbols": [s.name for s in self.symbols_by_file.get(file_path, [])],
        }
