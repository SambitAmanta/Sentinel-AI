"""Unit tests for AST Parser and Symbol Graph."""
import pytest
from pathlib import Path
from app.ast_engine.parser import ASTParser
from app.ast_engine.symbol_graph import SymbolGraph

def test_ast_parser_extracts_functions_and_calls(tmp_path):
    code = """
def helper(x):
    return x * 2

def process_data(items):
    total = 0
    for i in items:
        total += helper(i)
    return total
"""
    test_file = tmp_path / "sample.py"
    test_file.write_text(code, encoding="utf-8")

    parser = ASTParser()
    symbols = parser.parse_file(test_file)

    assert len(symbols) == 2
    names = [s.name for s in symbols]
    assert "helper" in names
    assert "process_data" in names

    proc_sym = next(s for s in symbols if s.name == "process_data")
    assert "helper" in proc_sym.calls

def test_symbol_graph_resolves_cross_file_dependencies(tmp_path):
    mod_a = tmp_path / "mod_a.py"
    mod_a.write_text("""
def calculate_tax(amount):
    return amount * 0.2
""", encoding="utf-8")

    mod_b = tmp_path / "mod_b.py"
    mod_b.write_text("""
from mod_a import calculate_tax

def checkout(cart_total):
    tax = calculate_tax(cart_total)
    return cart_total + tax
""", encoding="utf-8")

    graph = SymbolGraph()
    indexed_count = graph.index_directory(tmp_path)
    assert indexed_count == 2

    # Query enclosing function for line 3 in mod_a.py
    ctx = graph.get_context_for_vulnerability("mod_a.py", 3)
    assert ctx["enclosing_symbol"] is not None
    assert ctx["enclosing_symbol"].name == "calculate_tax"

    # Query callers of calculate_tax
    callers = graph.get_callers("calculate_tax")
    assert len(callers) == 1
    assert callers[0].name == "checkout"

