"""
Layer 2: Dependency graph construction from AST data.

Builds a dependency graph from parsed AST data, tracking imports,
trait implementations, and module structure.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List

from .ast_parser import FileAST


@dataclass
class FileImports:
    file: str
    imports_from: List[str] = field(default_factory=list)
    use_paths: List[str] = field(default_factory=list)


@dataclass
class TypeImplements:
    type_name: str
    defined_in: str
    implements: List[str] = field(default_factory=list)


@dataclass
class ModuleInfo:
    module_path: str
    file: str
    submodules: List[str] = field(default_factory=list)
    pub_items: List[str] = field(default_factory=list)


@dataclass
class DependencyGraph:
    imports: List[FileImports] = field(default_factory=list)
    implements: List[TypeImplements] = field(default_factory=list)
    modules: List[ModuleInfo] = field(default_factory=list)


def _extract_crate_from_use(use_stmt: str) -> str:
    """Extract the first path segment (crate name) from a use statement."""
    # Strip pub(crate) use prefix
    stmt = use_stmt.strip()
    for prefix in ("pub(crate) use ", "pub use ", "use "):
        if stmt.startswith(prefix):
            stmt = stmt[len(prefix):]
            break
    # First path segment
    parts = stmt.split("::")
    if parts:
        return parts[0].strip()
    return ""


def _extract_use_path(use_stmt: str) -> str:
    """Strip 'use' prefix and trailing ';' from a use statement."""
    stmt = use_stmt.strip()
    for prefix in ("pub(crate) use ", "pub use ", "use "):
        if stmt.startswith(prefix):
            stmt = stmt[len(prefix):]
            break
    if stmt.endswith(";"):
        stmt = stmt[:-1]
    return stmt.strip()


def _file_to_module_path(file_path: str) -> str:
    """Convert file path to module path.

    crates/X/Y/src/foo/bar.rs -> Y::foo::bar
    Replaces - with _ in module names.
    """
    parts = file_path.replace("\\", "/").split("/")

    # Find 'src' in the path
    try:
        src_idx = parts.index("src")
    except ValueError:
        return file_path.replace("/", "::").replace("-", "_")

    # Crate name is the part before src (could be crates/X/Y/src)
    # Use the part just before src
    crate_name = parts[src_idx - 1] if src_idx > 0 else ""

    # Module path is everything after src
    mod_parts = parts[src_idx + 1:]
    if mod_parts:
        # Remove .rs extension from last part
        last = mod_parts[-1]
        if last.endswith(".rs"):
            mod_parts[-1] = last[:-3]
        # Remove mod and lib
        if mod_parts[-1] in ("mod", "lib"):
            mod_parts = mod_parts[:-1]

    all_parts = [crate_name] + mod_parts if crate_name else mod_parts
    module_path = "::".join(all_parts)
    return module_path.replace("-", "_")


def build_dependency_graph(file_asts: List[FileAST]) -> DependencyGraph:
    """Build a dependency graph from parsed FileAST objects."""
    graph = DependencyGraph()

    seen_implements = set()

    for file_ast in file_asts:
        # Build imports
        if file_ast.use_statements:
            imports_from = []
            use_paths = []
            for use_stmt in file_ast.use_statements:
                crate = _extract_crate_from_use(use_stmt)
                if crate and crate not in imports_from:
                    imports_from.append(crate)
                path = _extract_use_path(use_stmt)
                if path:
                    use_paths.append(path)
            graph.imports.append(FileImports(
                file=file_ast.file_path,
                imports_from=imports_from,
                use_paths=use_paths,
            ))

        # Build implements
        for impl_block in file_ast.impl_blocks:
            if impl_block.trait_name:
                key = (impl_block.type_name, impl_block.trait_name, file_ast.file_path)
                if key not in seen_implements:
                    seen_implements.add(key)
                    # Check if type already has an entry
                    existing = None
                    for ti in graph.implements:
                        if ti.type_name == impl_block.type_name and ti.defined_in == file_ast.file_path:
                            existing = ti
                            break
                    if existing:
                        if impl_block.trait_name not in existing.implements:
                            existing.implements.append(impl_block.trait_name)
                    else:
                        graph.implements.append(TypeImplements(
                            type_name=impl_block.type_name,
                            defined_in=file_ast.file_path,
                            implements=[impl_block.trait_name],
                        ))

        # Build modules
        module_path = _file_to_module_path(file_ast.file_path)
        pub_items = []
        for s in file_ast.structs:
            if s.visibility and "pub" in s.visibility:
                pub_items.append(s.name)
        for e in file_ast.enums:
            if e.visibility and "pub" in e.visibility:
                pub_items.append(e.name)
        for t in file_ast.traits:
            if t.visibility and "pub" in t.visibility:
                pub_items.append(t.name)
        for fn in file_ast.functions:
            if fn.visibility and "pub" in fn.visibility:
                pub_items.append(fn.name)

        graph.modules.append(ModuleInfo(
            module_path=module_path,
            file=file_ast.file_path,
            submodules=file_ast.modules,
            pub_items=pub_items,
        ))

    return graph


def save_graph(graph: DependencyGraph, output_dir: str):
    """Save dependency graph to JSON files."""
    graph_dir = os.path.join(output_dir, "graph")
    os.makedirs(graph_dir, exist_ok=True)

    with open(os.path.join(graph_dir, "imports.json"), "w") as f:
        json.dump([asdict(i) for i in graph.imports], f, indent=2)

    with open(os.path.join(graph_dir, "implements.json"), "w") as f:
        json.dump([asdict(i) for i in graph.implements], f, indent=2)

    with open(os.path.join(graph_dir, "modules.json"), "w") as f:
        json.dump([asdict(m) for m in graph.modules], f, indent=2)


def load_graph(output_dir: str) -> DependencyGraph:
    """Load dependency graph from JSON files."""
    graph_dir = os.path.join(output_dir, "graph")

    graph = DependencyGraph()

    imports_path = os.path.join(graph_dir, "imports.json")
    if os.path.exists(imports_path):
        with open(imports_path, "r") as f:
            data = json.load(f)
            graph.imports = [FileImports(**i) for i in data]

    implements_path = os.path.join(graph_dir, "implements.json")
    if os.path.exists(implements_path):
        with open(implements_path, "r") as f:
            data = json.load(f)
            graph.implements = [TypeImplements(**i) for i in data]

    modules_path = os.path.join(graph_dir, "modules.json")
    if os.path.exists(modules_path):
        with open(modules_path, "r") as f:
            data = json.load(f)
            graph.modules = [ModuleInfo(**m) for m in data]

    return graph
