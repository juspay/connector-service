"""
Layer 3: LLM semantic summary generation.

Builds structured input from AST data and dependency graph,
then optionally uses an LLM to generate a high-level summary
of the codebase architecture and patterns.
"""

import json
import os
from collections import Counter
from dataclasses import asdict
from typing import Dict, List, Optional

from .ast_parser import FileAST
from .graph_builder import DependencyGraph


def _build_summary_input(file_asts: List[FileAST], graph: DependencyGraph) -> str:
    """Build structured text input for LLM summarization."""
    sections = []

    # Module Structure - crate file counts
    crate_counts: Counter = Counter()
    for fa in file_asts:
        parts = fa.file_path.replace("\\", "/").split("/")
        if "crates" in parts:
            idx = parts.index("crates")
            if idx + 1 < len(parts):
                crate_counts[parts[idx + 1]] += 1
            else:
                crate_counts["unknown"] += 1
        else:
            crate_counts["other"] += 1

    sections.append("## Module Structure")
    for crate, count in crate_counts.most_common():
        sections.append(f"  - {crate}: {count} files")

    # Key Type Definitions
    sections.append("\n## Key Type Definitions")

    # Public structs with fields and derives
    for fa in file_asts:
        for s in fa.structs:
            if s.visibility and "pub" in s.visibility:
                fields_str = ", ".join(s.fields[:5])
                if len(s.fields) > 5:
                    fields_str += f", ... ({len(s.fields)} total)"
                derives_str = ", ".join(s.derives) if s.derives else "none"
                sections.append(f"  - struct {s.name} [{fa.file_path}]")
                sections.append(f"    fields: {fields_str}")
                sections.append(f"    derives: {derives_str}")

    # Public enums with variants
    for fa in file_asts:
        for e in fa.enums:
            if e.visibility and "pub" in e.visibility:
                variants_str = ", ".join(e.variants[:5])
                if len(e.variants) > 5:
                    variants_str += f", ... ({len(e.variants)} total)"
                sections.append(f"  - enum {e.name} [{fa.file_path}]")
                sections.append(f"    variants: {variants_str}")

    # Public traits with methods
    for fa in file_asts:
        for t in fa.traits:
            if t.visibility and "pub" in t.visibility:
                methods_str = ", ".join(t.methods[:5])
                if len(t.methods) > 5:
                    methods_str += f", ... ({len(t.methods)} total)"
                sections.append(f"  - trait {t.name} [{fa.file_path}]")
                sections.append(f"    methods: {methods_str}")

    # Trait Implementations
    sections.append("\n## Trait Implementations")
    for ti in graph.implements:
        sections.append(f"  - {ti.type_name} implements {', '.join(ti.implements)} [{ti.defined_in}]")

    # Macro Usage Patterns
    sections.append("\n## Macro Usage Patterns")
    macro_counts: Counter = Counter()
    macro_examples: Dict[str, str] = {}
    for fa in file_asts:
        for m in fa.macro_calls:
            macro_counts[m.name] += 1
            if m.name not in macro_examples:
                macro_examples[m.name] = fa.file_path

    for macro_name, count in macro_counts.most_common(20):
        sections.append(f"  - {macro_name}: {count} uses (e.g. {macro_examples[macro_name]})")

    # Common Import Patterns
    sections.append("\n## Common Import Patterns")
    crate_usage: Counter = Counter()
    for fi in graph.imports:
        for crate in fi.imports_from:
            crate_usage[crate] += 1

    for crate, count in crate_usage.most_common(20):
        sections.append(f"  - {crate}: imported by {count} files")

    return "\n".join(sections)


SUMMARY_PROMPT = """You are analyzing a Rust payment processing codebase (Hyperswitch).
Below is structured information extracted from the codebase AST and dependency graph.

{summary_input}

Please provide a comprehensive analysis covering:

1. **Architecture Overview**: High-level structure, key crates, and their responsibilities.
2. **Connector Pattern**: How payment connectors are implemented, common traits and patterns.
3. **Key Types**: The most important types and their roles in the system.
4. **Coding Conventions**: Naming patterns, error handling, derive usage, macro patterns.
5. **Common Mistakes**: Based on the patterns, what are likely pitfalls for new contributors.

Be specific and reference actual type names, traits, and modules from the codebase.
"""


def generate_summary(
    file_asts: List[FileAST],
    graph: DependencyGraph,
    output_dir: str,
    ai_service=None,
) -> str:
    """Generate a codebase summary, optionally using an LLM."""
    summary_input = _build_summary_input(file_asts, graph)

    if ai_service is not None:
        try:
            prompt = SUMMARY_PROMPT.format(summary_input=summary_input)
            summary = ai_service.generate(prompt)
        except Exception:
            summary = f"# Codebase Summary (Structural Only)\n\n{summary_input}"
    else:
        summary = f"# Codebase Summary (Structural Only)\n\n{summary_input}"

    # Save summary
    os.makedirs(output_dir, exist_ok=True)
    summary_path = os.path.join(output_dir, "summary.md")
    with open(summary_path, "w") as f:
        f.write(summary)

    return summary


def _build_types_index(file_asts: List[FileAST], output_dir: str):
    """Build per-crate type indices and save to types/ directory."""
    types_dir = os.path.join(output_dir, "types")
    os.makedirs(types_dir, exist_ok=True)

    # Group by crate key
    crate_types: Dict[str, dict] = {}

    for fa in file_asts:
        parts = fa.file_path.replace("\\", "/").split("/")
        if len(parts) > 2:
            crate_key = "_".join(parts[1:3])
        else:
            crate_key = "_".join(parts)

        if crate_key not in crate_types:
            crate_types[crate_key] = {
                "structs": [],
                "enums": [],
                "traits": [],
            }

        for s in fa.structs:
            crate_types[crate_key]["structs"].append(asdict(s))
        for e in fa.enums:
            crate_types[crate_key]["enums"].append(asdict(e))
        for t in fa.traits:
            crate_types[crate_key]["traits"].append(asdict(t))

    # Write per-crate JSON
    for crate_key, types_data in crate_types.items():
        safe_key = crate_key.replace("/", "_").replace("\\", "_")
        out_path = os.path.join(types_dir, f"{safe_key}.json")
        with open(out_path, "w") as f:
            json.dump(types_data, f, indent=2)
