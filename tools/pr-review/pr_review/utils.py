"""Utility functions for rule implementations."""

from __future__ import annotations

import re


def is_comment_line(line: str) -> bool:
    """Check if a line is a Rust comment."""
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.startswith("///")
        or stripped.startswith("//!")
    )


def is_string_literal_context(line: str, match_start: int) -> bool:
    """Heuristic check if a match position is inside a string literal.

    This is a best-effort check - proper string detection requires
    full parsing, but this catches the most common cases.
    """
    # Count unescaped quotes before the match position
    prefix = line[:match_start]
    quote_count = 0
    i = 0
    while i < len(prefix):
        if prefix[i] == '"' and (i == 0 or prefix[i - 1] != "\\"):
            quote_count += 1
        i += 1
    # Odd number of quotes means we're inside a string
    return quote_count % 2 == 1


def is_in_test_module(content: str, line_number: int) -> bool:
    """Check if a line number falls within a #[cfg(test)] module.

    Args:
        content: Full file content.
        line_number: 1-indexed line number to check.

    Returns:
        True if the line is within a test module.
    """
    lines = content.split("\n")
    if line_number > len(lines):
        return False

    # Walk backwards from the line to find if we're in a test module
    in_test_section = False
    brace_depth = 0

    for i in range(line_number - 1, -1, -1):
        line = lines[i].strip()

        # Count braces to track scope
        brace_depth += line.count("}") - line.count("{")

        if "#[cfg(test)]" in line:
            if brace_depth <= 0:
                in_test_section = True
                break

    return in_test_section


def is_in_attribute(line: str) -> bool:
    """Check if the line is inside a Rust attribute (#[...])."""
    stripped = line.strip()
    return stripped.startswith("#[") or stripped.startswith("#![")


def extract_struct_fields(content: str) -> list[dict[str, str]]:
    """Extract struct field definitions from Rust source.

    Returns a list of dicts with 'name', 'type', and 'line_number' keys.
    """
    fields = []
    # Match struct fields: `pub field_name: FieldType,`
    pattern = re.compile(r"^\s*(?:pub\s+)?(\w+)\s*:\s*(.+?)\s*,?\s*$", re.MULTILINE)
    for i, line in enumerate(content.split("\n"), 1):
        m = pattern.match(line)
        if m:
            fields.append(
                {
                    "name": m.group(1),
                    "type": m.group(2).strip().rstrip(","),
                    "line_number": str(i),
                }
            )
    return fields


def find_pattern_in_content(
    content: str,
    pattern: str | re.Pattern[str],
) -> list[tuple[int, str]]:
    """Find all occurrences of a pattern in content.

    Returns list of (line_number, line_content) tuples.
    """
    if isinstance(pattern, str):
        pattern = re.compile(pattern)

    results = []
    for i, line in enumerate(content.split("\n"), 1):
        if pattern.search(line):
            results.append((i, line.strip()))
    return results
