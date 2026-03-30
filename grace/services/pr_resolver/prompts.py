"""Dynamic prompt builder for the PR Resolver's Claude agent session."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Max lines from summary.md to include in the prompt
_MAX_SUMMARY_LINES = 3000
# Caps for types
_MAX_STRUCTS = 50
_MAX_ENUMS = 30


def _load_summary(index_dir: Path) -> str:
    """Read ``summary.md`` and truncate to *_MAX_SUMMARY_LINES* lines."""
    summary_path = index_dir / "summary.md"
    if not summary_path.exists():
        logger.debug("No summary.md found at %s", summary_path)
        return ""
    lines = summary_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) > _MAX_SUMMARY_LINES:
        lines = lines[:_MAX_SUMMARY_LINES]
        lines.append("\n... (truncated)")
    return "\n".join(lines)


def _crate_for_path(file_path: str) -> Optional[str]:
    """Extract the crate name from a file path like ``crates/router/src/...``."""
    parts = file_path.replace("\\", "/").split("/")
    if "crates" in parts:
        idx = parts.index("crates")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _load_relevant_types(index_dir: Path, affected_files: List[str]) -> str:
    """Load type definitions for crates that own the affected files.

    Always includes ``domain_types`` and ``common_enums``.
    Caps output at *_MAX_STRUCTS* structs and *_MAX_ENUMS* enums.
    """
    types_dir = index_dir / "types"
    if not types_dir.exists():
        return ""

    # Determine which crates to load
    crates = {"domain_types", "common_enums"}
    for f in affected_files:
        crate = _crate_for_path(f)
        if crate:
            crates.add(crate)

    structs: List[Dict[str, Any]] = []
    enums: List[Dict[str, Any]] = []

    for crate in sorted(crates):
        crate_file = types_dir / f"{crate}.json"
        if not crate_file.exists():
            continue
        try:
            data = json.loads(crate_file.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        for entry in data if isinstance(data, list) else data.get("types", data.get("structs", [])):
            kind = entry.get("kind", "struct")
            if kind == "enum" and len(enums) < _MAX_ENUMS:
                enums.append(entry)
            elif len(structs) < _MAX_STRUCTS:
                structs.append(entry)

    if not structs and not enums:
        return ""

    parts = ["## Relevant Types\n"]
    if structs:
        parts.append("### Structs\n```json")
        parts.append(json.dumps(structs, indent=2, default=str)[:8000])
        parts.append("```\n")
    if enums:
        parts.append("### Enums\n```json")
        parts.append(json.dumps(enums, indent=2, default=str)[:4000])
        parts.append("```\n")
    return "\n".join(parts)


def _load_relevant_graph(index_dir: Path, affected_files: List[str]) -> str:
    """Load import and implements graph entries for affected files."""
    graph_dir = index_dir / "graph"
    if not graph_dir.exists():
        # Try flat files
        imports_file = index_dir / "imports.json"
        implements_file = index_dir / "implements.json"
        return _load_graph_flat(imports_file, implements_file, affected_files)

    parts = ["## Dependency Graph\n"]
    found_anything = False

    for name in ("imports", "implements"):
        graph_file = graph_dir / f"{name}.json"
        if not graph_file.exists():
            graph_file = index_dir / f"{name}.json"
        if not graph_file.exists():
            continue
        try:
            data = json.loads(graph_file.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        relevant: Dict[str, Any] = {}
        for file_path in affected_files:
            if file_path in data:
                relevant[file_path] = data[file_path]
            # Also try basename match
            base = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
            for key, val in data.items():
                if key.endswith(f"/{base}") or key == base:
                    relevant[key] = val

        if relevant:
            found_anything = True
            parts.append(f"### {name.title()}\n```json")
            parts.append(json.dumps(relevant, indent=2, default=str)[:4000])
            parts.append("```\n")

    return "\n".join(parts) if found_anything else ""


def _load_graph_flat(
    imports_file: Path, implements_file: Path, affected_files: List[str]
) -> str:
    """Fallback when graph data is in flat files."""
    parts = ["## Dependency Graph\n"]
    found = False
    for label, path in [("Imports", imports_file), ("Implements", implements_file)]:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        relevant = {k: v for k, v in data.items() if k in affected_files}
        if relevant:
            found = True
            parts.append(f"### {label}\n```json")
            parts.append(json.dumps(relevant, indent=2, default=str)[:4000])
            parts.append("```\n")
    return "\n".join(parts) if found else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_resolution_prompt(
    threads: List[Any],
    index_dir: Path,
) -> str:
    """Build the full system prompt for the Claude agent session.

    *threads* is a list of ``TriggeredThread`` objects.
    """
    affected_files = list({t.path for t in threads if t.path})

    # Load codebase context
    summary = _load_summary(index_dir)
    types_section = _load_relevant_types(index_dir, affected_files)
    graph_section = _load_relevant_graph(index_dir, affected_files)

    # Build per-comment section
    comments_section = "## Review Comments\n\n"
    for i, t in enumerate(threads, 1):
        comments_section += f"### Comment {i}\n"
        comments_section += f"- **File:** `{t.path}`\n"
        if t.line is not None:
            comments_section += f"- **Line:** {t.line}\n"
        comments_section += f"- **Reviewer:** {t.author}\n"
        comments_section += f"- **Instruction:** {t.instruction}\n"
        if t.diff_hunk:
            comments_section += f"- **Diff context:**\n```diff\n{t.diff_hunk}\n```\n"
        comments_section += "\n"

    prompt = f"""You are a code review resolver. Your task is to fix code based on review comments.

## Codebase Context

{summary}

{types_section}

{graph_section}

{comments_section}

## Instructions

1. **Read the affected files** to understand the current code.
2. **Apply the minimal fix** requested by each reviewer.
3. **Run `cargo check`** after making changes to verify the code compiles.
4. **If cargo check fails**, revert your changes and try a different approach.
5. **Do NOT add new dependencies** unless explicitly requested.
6. **Do NOT refactor** beyond what the reviewer asked for.

## Rules

- Make the smallest possible change that satisfies each review comment.
- Preserve existing code style and formatting.
- If a comment is ambiguous, prefer the safer/simpler interpretation.
- If you cannot resolve a comment, leave the code unchanged and explain why.
- Always verify your changes compile with `cargo check`.
"""
    return prompt
