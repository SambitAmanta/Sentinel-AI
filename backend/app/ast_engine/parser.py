"""Modern Tree-sitter AST parser for semantic code understanding and symbol extraction."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any

from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript

@dataclass
class CodeSymbol:
    name: str
    kind: str  # 'function', 'class', 'method'
    file_path: str
    line_start: int
    line_end: int
    content: str
    docstring: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)

class ASTParser:
    """Parses source files into structured AST nodes and extracts semantic boundaries."""

    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "tsx",
    }

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._init_parsers()

    def _init_parsers(self):
        py_lang = Language(tspython.language())
        self._parsers["python"] = Parser(py_lang)

        js_lang = Language(tsjavascript.language())
        self._parsers["javascript"] = Parser(js_lang)

        ts_lang = Language(tstypescript.language_typescript())
        self._parsers["typescript"] = Parser(ts_lang)

        tsx_lang = Language(tstypescript.language_tsx())
        self._parsers["tsx"] = Parser(tsx_lang)

    def get_parser_for_file(self, file_path: str | Path):
        ext = Path(file_path).suffix.lower()
        lang_name = self.SUPPORTED_EXTENSIONS.get(ext)
        if not lang_name or lang_name not in self._parsers:
            return None, None
        return self._parsers[lang_name], lang_name

    def parse_file(self, file_path: str | Path) -> List[CodeSymbol]:
        path = Path(file_path)
        parser, lang = self.get_parser_for_file(path)
        if not parser or not path.exists():
            return []

        try:
            with open(path, "rb") as f:
                code_bytes = f.read()
        except Exception:
            return []

        tree = parser.parse(code_bytes)
        root_node = tree.root_node
        symbols: List[CodeSymbol] = []

        if lang == "python":
            symbols.extend(self._extract_python_symbols(root_node, code_bytes, str(path)))
        elif lang in ("javascript", "typescript", "tsx"):
            symbols.extend(self._extract_js_ts_symbols(root_node, code_bytes, str(path)))

        return symbols

    def _extract_python_symbols(self, root_node, code_bytes: bytes, file_path: str) -> List[CodeSymbol]:
        symbols: List[CodeSymbol] = []

        def traverse(node):
            if node.type in ("function_definition", "async_function_definition"):
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode("utf-8") if name_node else "anonymous"
                
                # Parameters
                params_node = node.child_by_field_name("parameters")
                params = []
                if params_node:
                    for child in params_node.children:
                        if child.type == "identifier":
                            params.append(child.text.decode("utf-8"))

                # Extract calls inside function body
                calls = []
                for child in self._find_descendants(node, "call"):
                    func_id = child.child_by_field_name("function")
                    if func_id and func_id.type == "identifier":
                        calls.append(func_id.text.decode("utf-8"))

                content = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

                symbols.append(CodeSymbol(
                    name=name,
                    kind="function",
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    content=content,
                    parameters=params,
                    calls=calls,
                ))

            elif node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode("utf-8") if name_node else "anonymous"
                content = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

                symbols.append(CodeSymbol(
                    name=name,
                    kind="class",
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    content=content,
                ))

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _extract_js_ts_symbols(self, root_node, code_bytes: bytes, file_path: str) -> List[CodeSymbol]:
        symbols: List[CodeSymbol] = []

        def traverse(node):
            if node.type in ("function_declaration", "method_definition", "arrow_function"):
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode("utf-8") if name_node else "anonymous"
                
                content = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                symbols.append(CodeSymbol(
                    name=name,
                    kind="function",
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    content=content,
                ))
            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode("utf-8") if name_node else "anonymous"
                content = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                symbols.append(CodeSymbol(
                    name=name,
                    kind="class",
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    content=content,
                ))

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return symbols

    def _find_descendants(self, node, node_type: str) -> List[Any]:
        matches = []
        for child in node.children:
            if child.type == node_type:
                matches.append(child)
            matches.extend(self._find_descendants(child, node_type))
        return matches
