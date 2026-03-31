"""
Main indexer orchestrator.

Coordinates AST parsing, dependency graph construction, and summary
generation. Supports both full and incremental indexing.
"""

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .ast_parser import FileAST, RustASTParser, load_file_ast, save_file_ast
from .graph_builder import build_dependency_graph, save_graph
from .incremental import (
    get_all_rs_files,
    get_changed_rs_files,
    get_current_commit,
    get_deleted_rs_files,
    should_full_reindex,
)
from .summarizer import _build_types_index, generate_summary


@dataclass
class IndexMeta:
    version: str = "1.0"
    last_indexed: str = ""
    commit_sha: str = ""
    total_files: int = 0
    indexed_files: int = 0
    indexing_duration_seconds: float = 0.0
    incremental: bool = False


@dataclass
class IndexResult:
    success: bool = False
    meta: Optional[IndexMeta] = None
    errors: List[str] = field(default_factory=list)
    files_parsed: int = 0
    structs_found: int = 0
    enums_found: int = 0
    traits_found: int = 0
    impl_blocks_found: int = 0
    functions_found: int = 0


def _load_meta(output_dir: str) -> Optional[IndexMeta]:
    """Load previous index metadata."""
    meta_path = os.path.join(output_dir, "meta.json")
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path, "r") as f:
            data = json.load(f)
        return IndexMeta(**data)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def _save_meta(meta: IndexMeta, output_dir: str):
    """Save index metadata."""
    os.makedirs(output_dir, exist_ok=True)
    meta_path = os.path.join(output_dir, "meta.json")
    with open(meta_path, "w") as f:
        json.dump(asdict(meta), f, indent=2)


def _load_cached_asts(output_dir: str) -> Dict[str, FileAST]:
    """Load all cached AST files from previous index."""
    ast_dir = os.path.join(output_dir, "ast")
    cached = {}
    if not os.path.exists(ast_dir):
        return cached
    for fname in os.listdir(ast_dir):
        if fname.endswith(".json"):
            try:
                fpath = os.path.join(ast_dir, fname)
                file_ast = load_file_ast(fpath)
                cached[file_ast.file_path] = file_ast
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    return cached


def run_indexer(
    repo_path: str,
    output_dir: str = ".grace_index",
    force_full: bool = False,
    verbose: bool = False,
    ai_service=None,
) -> IndexResult:
    """Run the indexer on a Rust repository.

    Args:
        repo_path: Path to the repository root.
        output_dir: Directory to store index data.
        force_full: Force a full reindex.
        verbose: Print verbose output.
        ai_service: Optional AI service for LLM summary generation.

    Returns:
        IndexResult with indexing statistics.
    """
    start_time = time.time()
    result = IndexResult()

    try:
        from rich.progress import Progress
    except ImportError:
        Progress = None

    # Check for previous index
    prev_meta = _load_meta(output_dir)
    current_sha = get_current_commit(repo_path) or "unknown"

    # Determine files to index
    all_files = get_all_rs_files(repo_path)
    total_count = len(all_files)

    incremental = False
    files_to_parse = all_files
    deleted_files = []

    if not force_full and prev_meta and prev_meta.commit_sha:
        changed = get_changed_rs_files(repo_path, prev_meta.commit_sha)
        deleted_files = get_deleted_rs_files(repo_path, prev_meta.commit_sha)

        if not should_full_reindex(len(changed), total_count):
            incremental = True
            # Only parse changed files
            files_to_parse = [os.path.join(repo_path, f) for f in changed]
            if verbose:
                print(f"Incremental index: {len(changed)} changed, {len(deleted_files)} deleted")
        else:
            if verbose:
                print(f"Too many changes ({len(changed)}/{total_count}), doing full reindex")

    if verbose:
        print(f"Indexing {len(files_to_parse)} files (total: {total_count})")

    # Layer 1: AST parsing
    parser = RustASTParser()
    file_asts = []

    # Normalize: store relative paths (relative to repo root)
    def _make_relative(file_ast):
        """Convert absolute file_path to relative."""
        fp = file_ast.file_path
        if fp.startswith(repo_path):
            fp = fp[len(repo_path):].lstrip("/")
        elif fp.startswith(str(repo_path)):
            fp = fp[len(str(repo_path)):].lstrip("/")
        file_ast.file_path = fp
        return file_ast

    if Progress is not None:
        with Progress() as progress:
            task = progress.add_task("Parsing Rust files...", total=len(files_to_parse))
            for fpath in files_to_parse:
                ast = parser.parse_file(fpath)
                if ast:
                    file_asts.append(_make_relative(ast))
                else:
                    result.errors.append(f"Failed to parse: {fpath}")
                progress.update(task, advance=1)
    else:
        for fpath in files_to_parse:
            ast = parser.parse_file(fpath)
            if ast:
                file_asts.append(_make_relative(ast))
            else:
                result.errors.append(f"Failed to parse: {fpath}")

    # For incremental: merge with cached ASTs
    if incremental:
        cached = _load_cached_asts(output_dir)
        # Remove deleted files from cache
        for df in deleted_files:
            full_path = os.path.join(repo_path, df)
            cached.pop(full_path, None)
        # Update cache with newly parsed files
        for fa in file_asts:
            cached[fa.file_path] = fa
        # Use all cached + new as the full set
        all_asts = list(cached.values())
    else:
        all_asts = file_asts

    # Save AST files
    ast_dir = os.path.join(output_dir, "ast")
    os.makedirs(ast_dir, exist_ok=True)
    for fa in file_asts:
        save_file_ast(fa, ast_dir)

    # Layer 2: Build dependency graph
    graph = build_dependency_graph(all_asts)
    save_graph(graph, output_dir)

    # Layer 3: Generate summary
    generate_summary(all_asts, graph, output_dir, ai_service=ai_service)
    _build_types_index(all_asts, output_dir)

    # Compute stats
    duration = time.time() - start_time

    result.files_parsed = len(file_asts)
    for fa in all_asts:
        result.structs_found += len(fa.structs)
        result.enums_found += len(fa.enums)
        result.traits_found += len(fa.traits)
        result.impl_blocks_found += len(fa.impl_blocks)
        result.functions_found += len(fa.functions)

    # Save meta
    meta = IndexMeta(
        version="1.0",
        last_indexed=datetime.now(timezone.utc).isoformat(),
        commit_sha=current_sha,
        total_files=total_count,
        indexed_files=len(file_asts),
        indexing_duration_seconds=round(duration, 2),
        incremental=incremental,
    )
    _save_meta(meta, output_dir)

    result.success = True
    result.meta = meta
    return result
