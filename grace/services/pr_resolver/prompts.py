"""Dynamic prompt builder for the PR Resolver's Claude agent session."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Max lines from summary.md — keep it concise (conventions only, not full type dumps)
_MAX_SUMMARY_LINES = 200
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
    """Extract the crate key from a file path.

    crates/integrations/connector-integration/src/... -> integrations_connector_integration
    crates/common/common_enums/src/... -> common_common_enums
    """
    parts = file_path.replace("\\", "/").split("/")
    if "crates" in parts:
        idx = parts.index("crates")
        # Type files are named with parts[1:3] joined: integrations_connector_integration
        if idx + 2 < len(parts):
            return f"{parts[idx + 1]}_{parts[idx + 2]}".replace("-", "_")
        elif idx + 1 < len(parts):
            return parts[idx + 1].replace("-", "_")
    return None


def _load_relevant_types(index_dir: Path, affected_files: List[str]) -> str:
    """Load type definitions for crates that own the affected files.

    Always includes ``domain_types`` and ``common_enums``.
    Caps output at *_MAX_STRUCTS* structs and *_MAX_ENUMS* enums.
    """
    types_dir = index_dir / "types"
    if not types_dir.exists():
        return ""

    # Determine which crate type files to load
    crate_keys = set()
    for f in affected_files:
        key = _crate_for_path(f)
        if key:
            crate_keys.add(key)

    # Always include key type files
    for tf in types_dir.glob("*.json"):
        name = tf.stem
        if "domain_types" in name or "common_enums" in name:
            crate_keys.add(name)

    # Also match by the extracted keys
    for tf in types_dir.glob("*.json"):
        for key in list(crate_keys):
            if key in tf.stem or tf.stem in key:
                crate_keys.add(tf.stem)

    structs: List[Dict[str, Any]] = []
    enums: List[Dict[str, Any]] = []

    for crate in sorted(crate_keys):
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

        relevant: List[Any] = []
        # Handle both list format (from graph_builder) and dict format
        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            entry_file = entry.get("file", entry.get("defined_in", ""))
            for file_path in affected_files:
                base = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
                if entry_file == file_path or entry_file.endswith(f"/{base}") or base in entry_file:
                    relevant.append(entry)
                    break

        if relevant:
            found_anything = True
            parts.append(f"### {name.title()}\n```json")
            parts.append(json.dumps(relevant[:10], indent=2, default=str)[:4000])
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
        if isinstance(data, list):
            relevant = [e for e in data if isinstance(e, dict) and e.get("file", e.get("defined_in", "")) in affected_files]
        elif isinstance(data, dict):
            relevant = {k: v for k, v in data.items() if k in affected_files}
        else:
            relevant = []
        if relevant:
            found = True
            parts.append(f"### {label}\n```json")
            parts.append(json.dumps(relevant, indent=2, default=str)[:4000])
            parts.append("```\n")
    return "\n".join(parts) if found else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _build_comments_section(threads: List[Any]) -> str:
    """Format review comments into a prompt section."""
    parts = ["## Review Comments to Fix\n"]
    for i, t in enumerate(threads, 1):
        parts.append(f"### Comment {i} — `{t.path}:{t.line or '?'}` by @{t.author}")
        parts.append(f"**Instruction:** {t.instruction}")
        if t.diff_hunk:
            parts.append(f"**Code context:**\n```diff\n{t.diff_hunk}\n```")
        parts.append("")
    return "\n".join(parts)


def build_resolution_prompt(
    threads: List[Any],
    index_dir: Path,
    connector_name: str = "",
) -> str:
    """Build the prompt for a Claude agent session scoped to one connector.

    *threads* is a list of ``TriggeredThread`` objects (already filtered to one connector).
    *connector_name* focuses the index context on that connector's types/graph.
    """
    affected_files = list({t.path for t in threads if t.path})

    summary = _load_summary(index_dir)
    types_section = _load_relevant_types(index_dir, affected_files)
    graph_section = _load_relevant_graph(index_dir, affected_files)
    comments_section = _build_comments_section(threads)

    scope_note = f"connector `{connector_name}`" if connector_name else "the affected files"

    prompt = f"""You are an orchestrator resolving {len(threads)} PR review comment(s) on {scope_note}.

## Codebase Context

{summary}

{types_section}

{graph_section}

{comments_section}

## How to Resolve

You MUST use the **Agent tool** to spawn a separate subagent for EACH comment above. Do NOT make edits yourself directly — delegate each comment to a subagent.

For each comment, spawn an Agent like this:

```
Agent(
  subagent_type="general-purpose",
  description="Fix comment {N} on {connector_name}",
  prompt="Fix this review comment on `{{file}}:{{line}}`:

  Reviewer said: {{instruction}}

  Code context:
  ```
  {{diff_hunk}}
  ```

  Rules:
  - Read the file `{{file}}` to understand context
  - Make the MINIMAL edit to address the comment
  - ONLY modify files under connectors/{connector_name}/
  - Use RELATIVE paths (never /Users/...)
  - Do NOT run cargo build
  - After editing, output a 1-2 sentence summary of what you changed and why"
)
```

Process comments ONE AT A TIME — wait for each subagent to finish before starting the next, because they may edit the same file.

After ALL subagents finish, output a final summary listing what was changed for each comment:

```
## Summary
- Comment 1 (line X): Changed Y to Z because...
- Comment 2 (line X): Removed hardcoded value, now uses...
```

## Rules
- ONLY modify files under `connectors/{connector_name}/` or `connectors/{connector_name}.rs`
- Use RELATIVE paths for everything
- Do NOT run cargo build — the service verifies externally
"""
    # Strip absolute paths from index data — Claude should use relative paths in the clone
    import re
    prompt = re.sub(r'/Users/[^\s\]\)"]+/', '', prompt)

    return prompt


def build_fix_loop_prompt(
    threads: List[Any],
    error_output: str,
    loop_iteration: int,
    connector_name: str = "",
) -> str:
    """Build the prompt for a build-fix retry loop.

    Sent to Claude when cargo build or clippy fails after the initial fix attempt.
    Includes the original review comments + the build/clippy error output.
    """
    comments_section = _build_comments_section(threads)

    prompt = f"""You were resolving review comments on connector `{connector_name}`, but the build/clippy check failed.

This is fix attempt {loop_iteration}. Please fix the errors below while STILL addressing the original review comments.

## Original Review Comments

{comments_section}

## Build/Clippy Errors

```
{error_output}
```

## Instructions

1. Read the error messages carefully — they tell you exactly what's wrong.
2. Fix the errors while preserving the intent of the original review fixes.
3. If a fix is incompatible with building, revert that specific fix and leave the code as it was.
4. ONLY modify files under `connectors/{connector_name}/` or `connectors/{connector_name}.rs`.
5. Do NOT run cargo build yourself — the service will verify externally.
6. Use RELATIVE paths for all Read/Edit operations — never use absolute paths starting with /Users/.
"""
    # Strip absolute paths from error output
    import re
    prompt = re.sub(r'/Users/[^\s\]\)"]+/', '', prompt)

    return prompt
