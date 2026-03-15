"""Type safety rules for Rust code.

Detects usage of unwrap, expect, panic, todo, unsafe, as-casts,
println/eprintln/dbg, and other patterns that violate the strict
Clippy lint configuration of connector-service.
"""

from __future__ import annotations

from pr_review.rules.base import (
    Rule,
    RegexLineRule,
    Severity,
    Category,
)


def _lint_context(
    learned_data: dict | None, clippy_lint: str, rust_lint: str | None = None
) -> str | None:
    """Build a context string from learned lint level data.

    Returns a context string like 'Workspace Clippy config warns on unwrap_used.'
    or None if no learned data and no lint name provided.
    """
    if learned_data is None:
        return None  # Caller will use its own default

    lints = learned_data.get("lints", {})

    # Check clippy lints first
    clippy = lints.get("clippy", {})
    level = clippy.get(clippy_lint)
    if level:
        verb = {
            "warn": "warns on",
            "deny": "denies",
            "forbid": "forbids",
            "allow": "allows",
        }.get(level, f"sets {level} for")
        return f"Workspace Clippy config {verb} {clippy_lint}."

    # Check rust lints
    if rust_lint:
        rust = lints.get("rust", {})
        level = rust.get(rust_lint)
        if level:
            verb = {
                "warn": "warns on",
                "deny": "denies",
                "forbid": "forbids",
                "allow": "allows",
            }.get(level, f"sets {level} for")
            return f"Workspace Rust config {verb} {rust_lint}."

    return None


def get_rules(learned_data: dict | None = None) -> list[Rule]:
    """Return all type safety rules.

    Args:
        learned_data: Optional dict from learner.py with clippy lint levels.
    """
    # Build context strings from learned data or use defaults
    ts001_context = (
        _lint_context(learned_data, "unwrap_used")
        or "Workspace Clippy config warns on unwrap_used. Use error_stack for propagation."
    )
    ts002_context = (
        _lint_context(learned_data, "expect_used")
        or "Workspace Clippy config warns on expect_used."
    )
    ts003_context = (
        _lint_context(learned_data, "panic")
        or "Workspace Clippy config warns on panic."
    )
    ts005_context = (
        _lint_context(learned_data, "", "unsafe_code")
        or 'Cargo.toml workspace lints: unsafe_code = "forbid".'
    )
    ts006_context = (
        _lint_context(learned_data, "as_conversions")
        or "Workspace Clippy config warns on as_conversions."
    )
    ts007_context = (
        _lint_context(learned_data, "print_stdout")
        or "Workspace Clippy config warns on print_stdout and print_stderr."
    )
    ts008_context = (
        _lint_context(learned_data, "unreachable")
        or "Workspace Clippy config warns on unreachable."
    )
    ts009_context = (
        _lint_context(learned_data, "indexing_slicing")
        or "Workspace Clippy config warns on indexing_slicing."
    )

    return [
        RegexLineRule(
            rule_id="TS-001",
            name="No unwrap() calls",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            description="unwrap() can panic at runtime. Use proper error handling with ? or match.",
            pattern=r"\.unwrap\(\)",
            message_template="`.unwrap()` call detected. This can cause a runtime panic.",
            suggestion="Use `?` operator, `.ok_or()`, `.map_err()`, or pattern matching instead.",
            context=ts001_context,
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[
                r"^\s*//",  # Line comments
                r"^\s*\*",  # Block comment continuation
                r"^\s*/\*",  # Block comment start
                r"#\[allow\(",  # Allow attributes
            ],
        ),
        RegexLineRule(
            rule_id="TS-002",
            name="No expect() calls",
            severity=Severity.WARNING,
            category=Category.TYPE_SAFETY,
            description="expect() can panic at runtime. Use proper error handling.",
            pattern=r"\.expect\(",
            message_template="`.expect()` call detected. This can cause a runtime panic.",
            suggestion="Use `?` operator with `.ok_or()` or `.map_err()` for descriptive errors.",
            context=ts002_context,
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*/\*",
                r"#\[allow\(",
            ],
        ),
        RegexLineRule(
            rule_id="TS-003",
            name="No panic!() macro",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            description="panic!() causes the program to crash. Use Result types for error handling.",
            pattern=r"\bpanic!\s*\(",
            message_template="`panic!()` macro detected. This will crash the process.",
            suggestion="Return an error using `Err(report!(ConnectorError::...))` instead.",
            context=ts003_context,
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="TS-004",
            name="No todo!() / unimplemented!()",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            description="todo!() and unimplemented!() are placeholders that panic at runtime.",
            pattern=r"\b(todo|unimplemented)!\s*\(",
            message_template="Placeholder macro detected. This will panic at runtime.",
            suggestion="Implement the functionality or return a NotImplemented error.",
            context="These should never be in production code. Use ConnectorError::NotImplemented.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="TS-005",
            name="No unsafe blocks",
            severity=Severity.CRITICAL,
            category=Category.TYPE_SAFETY,
            description="unsafe code is forbidden in the connector-service workspace.",
            pattern=r"\bunsafe\s*\{",
            message_template="`unsafe` block detected. Unsafe code is forbidden in this workspace.",
            suggestion='Find a safe alternative. The workspace has `unsafe_code = "forbid"`.',
            context=ts005_context,
            exclude_test_files=False,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="TS-006",
            name="No as type casts for numeric types",
            severity=Severity.SUGGESTION,
            category=Category.TYPE_SAFETY,
            description="'as' casts can silently truncate or lose data. Use TryFrom/TryInto.",
            pattern=r"\bas\s+(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64)\b",
            message_template="Numeric `as` cast detected. This can silently truncate values.",
            suggestion="Use `TryFrom`/`TryInto` with proper error handling, or `From` if the conversion is infallible.",
            context=ts006_context,
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*", r"^\s*///"],
        ),
        RegexLineRule(
            rule_id="TS-007",
            name="No println!/eprintln!/dbg!",
            severity=Severity.WARNING,
            category=Category.TYPE_SAFETY,
            description="Use the structured tracing logger (logger::info!, logger::debug!, etc.) instead of print macros.",
            pattern=r"\b(println|eprintln|dbg)!\s*\(",
            message_template="Print macro detected. Use structured logging via `logger::*` instead.",
            suggestion="Replace with `logger::info!(...)`, `logger::debug!(...)`, etc.",
            context=ts007_context,
            file_filter=r"backend/",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="TS-008",
            name="No unreachable!() macro",
            severity=Severity.WARNING,
            category=Category.TYPE_SAFETY,
            description="unreachable!() panics at runtime. Ensure all code paths are handled.",
            pattern=r"\bunreachable!\s*\(",
            message_template="`unreachable!()` macro detected. This will panic if reached.",
            suggestion="Handle all cases explicitly or return an appropriate error.",
            context=ts008_context,
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="TS-009",
            name="No direct indexing with []",
            severity=Severity.SUGGESTION,
            category=Category.TYPE_SAFETY,
            description="Direct indexing can panic on out-of-bounds. Use .get() instead.",
            # Match array/vec indexing like `arr[0]`, `vec[i]` but not generic params like `Vec<T>`
            # or trait bounds like `impl Trait[T]` or attribute syntax
            pattern=r"(?<!\w<)\w+\[\s*\d+\s*\]",
            message_template="Direct indexing detected. This can panic on out-of-bounds access.",
            suggestion="Use `.get(index)` which returns `Option<&T>` for safe access.",
            context=ts009_context,
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"#\[",  # Attributes
                r"serde",  # Serde attributes
                r"derive",  # Derive macros
            ],
        ),
    ]
