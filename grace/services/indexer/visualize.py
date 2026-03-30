"""
Index visualization with Rich tables and trees.

Provides a CLI for exploring the indexed codebase data
with formatted output.
"""

import json
import os
from collections import Counter

import click
from rich.console import Console
from rich.table import Table
from rich.tree import Tree


console = Console()


def _load_meta(index_dir: str) -> dict:
    """Load meta.json."""
    meta_path = os.path.join(index_dir, "meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            return json.load(f)
    return {}


def _load_ast_files(index_dir: str) -> list:
    """Load all AST JSON files."""
    ast_dir = os.path.join(index_dir, "ast")
    asts = []
    if not os.path.exists(ast_dir):
        return asts
    for fname in sorted(os.listdir(ast_dir)):
        if fname.endswith(".json"):
            with open(os.path.join(ast_dir, fname), "r") as f:
                asts.append(json.load(f))
    return asts


def _load_graph(index_dir: str) -> dict:
    """Load graph JSON files."""
    graph_dir = os.path.join(index_dir, "graph")
    graph = {}
    for name in ("imports", "implements", "modules"):
        path = os.path.join(graph_dir, f"{name}.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                graph[name] = json.load(f)
        else:
            graph[name] = []
    return graph


def show_meta(index_dir: str):
    """Show index metadata as a table."""
    meta = _load_meta(index_dir)
    if not meta:
        console.print("[red]No meta.json found[/red]")
        return

    table = Table(title="Index Metadata")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Commit", meta.get("commit_sha", "N/A")[:12])
    table.add_row("Timestamp", meta.get("last_indexed", "N/A"))
    table.add_row("Total Files", str(meta.get("total_files", 0)))
    table.add_row("Indexed Files", str(meta.get("indexed_files", 0)))
    table.add_row("Duration (s)", str(meta.get("indexing_duration_seconds", 0)))
    table.add_row("Incremental", str(meta.get("incremental", False)))
    table.add_row("Version", meta.get("version", "N/A"))

    console.print(table)


def show_stats(index_dir: str):
    """Show per-crate statistics."""
    asts = _load_ast_files(index_dir)
    if not asts:
        console.print("[red]No AST data found[/red]")
        return

    # Group by crate
    crate_stats: dict = {}
    for ast in asts:
        fp = ast.get("file_path", "")
        parts = fp.replace("\\", "/").split("/")
        if "crates" in parts:
            idx = parts.index("crates")
            crate = parts[idx + 1] if idx + 1 < len(parts) else "unknown"
        else:
            crate = "other"

        if crate not in crate_stats:
            crate_stats[crate] = {
                "files": 0, "structs": 0, "enums": 0,
                "traits": 0, "impls": 0, "functions": 0, "macros": 0,
            }
        crate_stats[crate]["files"] += 1
        crate_stats[crate]["structs"] += len(ast.get("structs", []))
        crate_stats[crate]["enums"] += len(ast.get("enums", []))
        crate_stats[crate]["traits"] += len(ast.get("traits", []))
        crate_stats[crate]["impls"] += len(ast.get("impl_blocks", []))
        crate_stats[crate]["functions"] += len(ast.get("functions", []))
        crate_stats[crate]["macros"] += len(ast.get("macro_calls", []))

    table = Table(title="Crate Statistics")
    table.add_column("Crate", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Structs", justify="right")
    table.add_column("Enums", justify="right")
    table.add_column("Traits", justify="right")
    table.add_column("Impls", justify="right")
    table.add_column("Functions", justify="right")
    table.add_column("Macros", justify="right")

    totals = {"files": 0, "structs": 0, "enums": 0, "traits": 0, "impls": 0, "functions": 0, "macros": 0}

    for crate in sorted(crate_stats.keys()):
        s = crate_stats[crate]
        table.add_row(
            crate,
            str(s["files"]), str(s["structs"]), str(s["enums"]),
            str(s["traits"]), str(s["impls"]), str(s["functions"]), str(s["macros"]),
        )
        for k in totals:
            totals[k] += s[k]

    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{totals['files']}[/bold]",
        f"[bold]{totals['structs']}[/bold]",
        f"[bold]{totals['enums']}[/bold]",
        f"[bold]{totals['traits']}[/bold]",
        f"[bold]{totals['impls']}[/bold]",
        f"[bold]{totals['functions']}[/bold]",
        f"[bold]{totals['macros']}[/bold]",
    )

    console.print(table)


def show_connectors(index_dir: str):
    """Show connector information."""
    asts = _load_ast_files(index_dir)
    if not asts:
        console.print("[red]No AST data found[/red]")
        return

    connectors: dict = {}
    for ast in asts:
        fp = ast.get("file_path", "")
        if "connectors" not in fp:
            continue
        parts = fp.replace("\\", "/").split("/")
        if "connectors" in parts:
            idx = parts.index("connectors")
            if idx + 1 < len(parts):
                connector_name = parts[idx + 1]
                # If it's a file, use it directly; if dir, use dir name
                if connector_name.endswith(".rs"):
                    connector_name = connector_name[:-3]

                if connector_name not in connectors:
                    connectors[connector_name] = {
                        "files": 0, "structs": 0, "enums": 0, "impls": 0, "key_macros": [],
                    }
                connectors[connector_name]["files"] += 1
                connectors[connector_name]["structs"] += len(ast.get("structs", []))
                connectors[connector_name]["enums"] += len(ast.get("enums", []))
                connectors[connector_name]["impls"] += len(ast.get("impl_blocks", []))
                for m in ast.get("macro_calls", []):
                    macro_name = m.get("name", "")
                    if macro_name and macro_name not in connectors[connector_name]["key_macros"]:
                        connectors[connector_name]["key_macros"].append(macro_name)

    table = Table(title="Connectors")
    table.add_column("Name", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Structs", justify="right")
    table.add_column("Enums", justify="right")
    table.add_column("Impls", justify="right")
    table.add_column("Key Macros", width=40)

    for name in sorted(connectors.keys()):
        c = connectors[name]
        macros_str = ", ".join(c["key_macros"][:5])
        if len(c["key_macros"]) > 5:
            macros_str += f" (+{len(c['key_macros']) - 5})"
        table.add_row(
            name,
            str(c["files"]), str(c["structs"]), str(c["enums"]),
            str(c["impls"]), macros_str,
        )

    console.print(table)


def show_types(index_dir: str):
    """Show top 20 types by trait implementation count."""
    graph = _load_graph(index_dir)
    implements = graph.get("implements", [])

    if not implements:
        console.print("[red]No implementation data found[/red]")
        return

    # Count trait implementations per type
    type_impl_count: Counter = Counter()
    type_traits: dict = {}
    for entry in implements:
        tn = entry.get("type_name", "")
        traits = entry.get("implements", [])
        type_impl_count[tn] += len(traits)
        if tn not in type_traits:
            type_traits[tn] = []
        type_traits[tn].extend(traits)

    table = Table(title="Top 20 Types by Trait Implementations")
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Traits", width=60)

    for type_name, count in type_impl_count.most_common(20):
        traits_str = ", ".join(sorted(set(type_traits[type_name]))[:5])
        if len(set(type_traits[type_name])) > 5:
            traits_str += " ..."
        table.add_row(type_name, str(count), traits_str)

    console.print(table)


def show_imports(index_dir: str):
    """Show most imported crates with bar chart."""
    graph = _load_graph(index_dir)
    imports = graph.get("imports", [])

    if not imports:
        console.print("[red]No import data found[/red]")
        return

    crate_usage: Counter = Counter()
    for entry in imports:
        for crate in entry.get("imports_from", []):
            crate_usage[crate] += 1

    max_count = max(crate_usage.values()) if crate_usage else 1

    console.print("\n[bold]Most Imported Crates[/bold]\n")
    for crate, count in crate_usage.most_common(25):
        bar_len = int((count / max_count) * 40)
        bar = "\u2588" * bar_len
        console.print(f"  {crate:<30} {bar} {count}")

    console.print()


def show_tree(index_dir: str):
    """Show module hierarchy as a Rich Tree (top 3 levels)."""
    graph = _load_graph(index_dir)
    modules = graph.get("modules", [])

    if not modules:
        console.print("[red]No module data found[/red]")
        return

    tree = Tree("[bold]Codebase[/bold]")
    module_tree: dict = {}

    for mod in modules:
        mp = mod.get("module_path", "")
        parts = mp.split("::")
        # Limit to top 3 levels
        parts = parts[:3]

        current = module_tree
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]

    def _build_tree(tree_node, data, depth=0):
        if depth >= 3:
            return
        for key in sorted(data.keys()):
            child = tree_node.add(key)
            _build_tree(child, data[key], depth + 1)

    _build_tree(tree, module_tree)
    console.print(tree)


@click.command()
@click.option("--index-dir", default=".grace_index", help="Path to the index directory.")
@click.option(
    "--section",
    type=click.Choice(["meta", "stats", "connectors", "types", "imports", "tree"]),
    default="meta",
    help="Section to display.",
)
def main(index_dir, section):
    """Visualize Grace index data."""
    if not os.path.exists(index_dir):
        console.print(f"[red]Index directory not found: {index_dir}[/red]")
        return

    sections = {
        "meta": show_meta,
        "stats": show_stats,
        "connectors": show_connectors,
        "types": show_types,
        "imports": show_imports,
        "tree": show_tree,
    }

    fn = sections.get(section)
    if fn:
        fn(index_dir)


if __name__ == "__main__":
    main()
