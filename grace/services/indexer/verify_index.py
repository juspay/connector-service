"""
Index verification script.

Validates the generated index against the actual codebase by
cross-referencing grep counts with AST-parsed counts.
"""

import json
import os
import subprocess
from pathlib import Path

from rich.console import Console
from rich.table import Table


console = Console()


def _run_grep_count(repo_path: str, pattern: str) -> int:
    """Run grep and count matches."""
    try:
        result = subprocess.run(
            ["grep", "-r", "--include=*.rs", "-c", pattern, repo_path],
            capture_output=True,
            text=True,
        )
        total = 0
        for line in result.stdout.strip().split("\n"):
            if ":" in line:
                try:
                    total += int(line.rsplit(":", 1)[1])
                except ValueError:
                    pass
        return total
    except subprocess.CalledProcessError:
        return 0


def _check(name: str, passed: bool, detail: str = "") -> str:
    """Format a check result."""
    status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
    return status, name, detail


def _check_warn(name: str, value: float, threshold: float, detail: str = ""):
    """Format a check result with warning threshold."""
    if value <= threshold:
        return "[green]PASS[/green]", name, detail
    elif value <= threshold * 1.5:
        return "[yellow]WARN[/yellow]", name, detail
    else:
        return "[red]FAIL[/red]", name, detail


def verify_index(repo_path: str, index_dir: str):
    """Run all verification checks on the index."""
    results = []

    # 1. Index structure check
    required_items = ["meta.json", "summary.md", "types", "graph", "ast"]
    all_exist = True
    missing = []
    for item in required_items:
        path = os.path.join(index_dir, item)
        if not os.path.exists(path):
            all_exist = False
            missing.append(item)

    results.append(_check(
        "Index structure",
        all_exist,
        f"Missing: {', '.join(missing)}" if missing else "All required files/dirs present",
    ))

    # 2. Meta check
    meta_path = os.path.join(index_dir, "meta.json")
    meta_ok = False
    meta_detail = ""
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            meta = json.load(f)
        has_sha = bool(meta.get("commit_sha"))
        has_files = meta.get("total_files", 0) > 0
        meta_ok = has_sha and has_files
        meta_detail = f"commit={meta.get('commit_sha', 'N/A')[:8]}, files={meta.get('total_files', 0)}"
    else:
        meta_detail = "meta.json not found"

    results.append(_check("Meta check", meta_ok, meta_detail))

    # 3. Struct count: grep vs AST
    grep_structs = _run_grep_count(os.path.join(repo_path, "crates"), r"^pub struct ")
    ast_structs = _count_from_ast(index_dir, "structs")
    if grep_structs > 0:
        diff_ratio = abs(grep_structs - ast_structs) / grep_structs
        results.append(_check_warn(
            "Struct count",
            diff_ratio,
            0.15,
            f"grep={grep_structs}, ast={ast_structs}, diff={diff_ratio:.1%}",
        ))
    else:
        results.append(_check("Struct count", ast_structs > 0, f"ast={ast_structs}"))

    # 4. Enum count: grep vs AST
    grep_enums = _run_grep_count(os.path.join(repo_path, "crates"), r"^pub enum ")
    ast_enums = _count_from_ast(index_dir, "enums")
    if grep_enums > 0:
        diff_ratio = abs(grep_enums - ast_enums) / grep_enums
        results.append(_check_warn(
            "Enum count",
            diff_ratio,
            0.15,
            f"grep={grep_enums}, ast={ast_enums}, diff={diff_ratio:.1%}",
        ))
    else:
        results.append(_check("Enum count", ast_enums > 0, f"ast={ast_enums}"))

    # 5. Spot checks
    spot_checks = [
        ("RouterDataV2", "structs"),
        ("ConnectorError", "enums"),
        ("PaymentMethod", "enums"),
    ]
    for type_name, category in spot_checks:
        found = _find_type_in_ast(index_dir, type_name, category)
        results.append(_check(
            f"Spot check: {type_name}",
            found,
            f"Found in {category}" if found else f"Not found in {category}",
        ))

    # 6. Connector count
    connectors_dir = os.path.join(repo_path, "crates", "hyperswitch_connectors", "src", "connectors")
    if os.path.exists(connectors_dir):
        connector_dirs = [
            d for d in os.listdir(connectors_dir)
            if os.path.isdir(os.path.join(connectors_dir, d))
        ]
        indexed_connectors = _count_connector_files(index_dir, connectors_dir)
        all_indexed = indexed_connectors >= len(connector_dirs)
        results.append(_check(
            "Connector count",
            all_indexed,
            f"dirs={len(connector_dirs)}, indexed={indexed_connectors}",
        ))
    else:
        results.append(_check("Connector count", False, "Connectors directory not found"))

    # 7. Macro detection
    grep_macros = _run_grep_count(
        os.path.join(repo_path, "crates"),
        "create_all_prerequisites",
    )
    ast_macros = _count_macro_in_ast(index_dir, "create_all_prerequisites")
    if grep_macros > 0:
        diff_ratio = abs(grep_macros - ast_macros) / grep_macros
        results.append(_check_warn(
            "Macro detection (create_all_prerequisites)",
            diff_ratio,
            0.30,
            f"grep={grep_macros}, ast={ast_macros}, diff={diff_ratio:.1%}",
        ))
    else:
        results.append(_check(
            "Macro detection",
            True,
            "No create_all_prerequisites macros found in grep",
        ))

    # 8. Graph integrity
    graph_dir = os.path.join(index_dir, "graph")
    graph_files = ["imports.json", "implements.json", "modules.json"]
    graph_ok = True
    graph_detail_parts = []
    for gf in graph_files:
        gpath = os.path.join(graph_dir, gf)
        if os.path.exists(gpath):
            with open(gpath, "r") as f:
                data = json.load(f)
            if len(data) == 0:
                graph_ok = False
                graph_detail_parts.append(f"{gf}: empty")
            else:
                graph_detail_parts.append(f"{gf}: {len(data)} entries")
        else:
            graph_ok = False
            graph_detail_parts.append(f"{gf}: missing")

    results.append(_check(
        "Graph integrity",
        graph_ok,
        ", ".join(graph_detail_parts),
    ))

    # Print results
    table = Table(title="Index Verification Results")
    table.add_column("Status", justify="center", width=8)
    table.add_column("Check", width=40)
    table.add_column("Detail", width=60)

    for status, name, detail in results:
        table.add_row(status, name, detail)

    console.print(table)

    # Summary
    pass_count = sum(1 for s, _, _ in results if "PASS" in s)
    fail_count = sum(1 for s, _, _ in results if "FAIL" in s)
    warn_count = sum(1 for s, _, _ in results if "WARN" in s)
    console.print(f"\n{pass_count} passed, {warn_count} warnings, {fail_count} failed")

    return fail_count == 0


def _count_from_ast(index_dir: str, category: str) -> int:
    """Count items of a category across all AST files."""
    ast_dir = os.path.join(index_dir, "ast")
    if not os.path.exists(ast_dir):
        return 0
    total = 0
    for fname in os.listdir(ast_dir):
        if fname.endswith(".json"):
            with open(os.path.join(ast_dir, fname), "r") as f:
                data = json.load(f)
            total += len(data.get(category, []))
    return total


def _find_type_in_ast(index_dir: str, type_name: str, category: str) -> bool:
    """Check if a specific type exists in the AST data."""
    ast_dir = os.path.join(index_dir, "ast")
    if not os.path.exists(ast_dir):
        return False
    for fname in os.listdir(ast_dir):
        if fname.endswith(".json"):
            with open(os.path.join(ast_dir, fname), "r") as f:
                data = json.load(f)
            for item in data.get(category, []):
                if item.get("name") == type_name:
                    return True
    return False


def _count_connector_files(index_dir: str, connectors_dir: str) -> int:
    """Count connector directories that have indexed files."""
    ast_dir = os.path.join(index_dir, "ast")
    if not os.path.exists(ast_dir):
        return 0
    indexed_files = set()
    for fname in os.listdir(ast_dir):
        if fname.endswith(".json"):
            with open(os.path.join(ast_dir, fname), "r") as f:
                data = json.load(f)
            fp = data.get("file_path", "")
            indexed_files.add(fp)

    connector_dirs = [
        d for d in os.listdir(connectors_dir)
        if os.path.isdir(os.path.join(connectors_dir, d))
    ]
    indexed_count = 0
    for cd in connector_dirs:
        # Check if any indexed file contains this connector dir
        for fp in indexed_files:
            if cd in fp:
                indexed_count += 1
                break
    return indexed_count


def _count_macro_in_ast(index_dir: str, macro_name: str) -> int:
    """Count occurrences of a specific macro in AST data."""
    ast_dir = os.path.join(index_dir, "ast")
    if not os.path.exists(ast_dir):
        return 0
    total = 0
    for fname in os.listdir(ast_dir):
        if fname.endswith(".json"):
            with open(os.path.join(ast_dir, fname), "r") as f:
                data = json.load(f)
            for macro in data.get("macro_calls", []):
                if macro.get("name") == macro_name:
                    total += 1
    return total


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python verify_index.py <repo_path> <index_dir>")
        sys.exit(1)

    success = verify_index(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)
