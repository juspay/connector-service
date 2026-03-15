"""Error handling rules.

Enforces proper error_stack usage, prevents hardcoded fallback values,
validates proper error propagation patterns.
"""

from __future__ import annotations

from pr_review.rules.base import (
    Rule,
    RegexLineRule,
    Severity,
    Category,
)


def get_rules() -> list[Rule]:
    """Return all error handling rules."""
    return [
        RegexLineRule(
            rule_id="EH-001",
            name="No hardcoded fallback values with unwrap_or",
            severity=Severity.WARNING,
            category=Category.ERROR_HANDLING,
            description="Hardcoded fallback values mask errors. Propagate errors properly.",
            # Match .unwrap_or("string literal") or .unwrap_or_else(|| "string")
            pattern=r"""\.unwrap_or\(\s*["']""",
            message_template="Hardcoded fallback value detected with `unwrap_or()`.",
            suggestion='Use `.ok_or(errors::ConnectorError::MissingRequiredField { field_name: "..." })?` instead.',
            context=(
                "Hardcoded defaults hide data issues. If a value is required, "
                "propagate the error. If optional, use Option<T> explicitly."
            ),
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="EH-002",
            name="No unwrap_or_else with hardcoded strings",
            severity=Severity.WARNING,
            category=Category.ERROR_HANDLING,
            description="unwrap_or_else with hardcoded fallbacks masks errors.",
            pattern=r"""\.unwrap_or_else\(\s*\|[^|]*\|\s*["']""",
            message_template="Hardcoded fallback value in `unwrap_or_else()`.",
            suggestion="Propagate the error with `?` or use a meaningful default from the domain.",
            context='Example: .unwrap_or_else(|| "missing-id".to_string()) should be .ok_or(ConnectorError::MissingRequiredField)?',
            file_filter=r"backend/connector-integration/",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="EH-003",
            name="Use change_context for error conversion",
            severity=Severity.SUGGESTION,
            category=Category.ERROR_HANDLING,
            description="When converting between error types, use .change_context() from error_stack.",
            # Detect .map_err(|_| report!(...)) which could be simplified
            pattern=r"""\.map_err\(\s*\|_\|\s*report!\(""",
            message_template="Consider using `.change_context()` instead of `.map_err(|_| report!(...))`.",
            suggestion="Use `.change_context(ConnectorError::...)` for cleaner error conversion that preserves the chain.",
            context="change_context() preserves the original error in the error_stack chain for better debugging.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
        RegexLineRule(
            rule_id="EH-004",
            name="Use descriptive error messages with attach_printable",
            severity=Severity.SUGGESTION,
            category=Category.ERROR_HANDLING,
            description="Error context should include relevant details via attach_printable.",
            # Detect change_context without attach_printable
            pattern=r"""\.change_context\([^)]+\)\s*\?""",
            message_template="Consider adding `.attach_printable()` for additional error context.",
            suggestion='Add `.attach_printable("description of what was being done")` before `?`.',
            context="attach_printable adds human-readable context to the error_stack chain without changing the error type.",
            file_filter=r"backend/connector-integration/src/connectors/\w+\.rs$",
            exclude_test_files=True,
            exclude_patterns=[
                r"^\s*//",
                r"^\s*\*",
                r"attach_printable",  # Already has it
            ],
        ),
        RegexLineRule(
            rule_id="EH-005",
            name="Use get_required_value, not get_optional for required fields",
            severity=Severity.WARNING,
            category=Category.ERROR_HANDLING,
            description="When a field is required by a connector, use the required accessor, not optional.",
            # Heuristic: detect get_optional_* followed by unwrap_or or similar
            pattern=r"""get_optional_\w+\(\).*\.unwrap_or""",
            message_template="Optional accessor used for what appears to be a required field.",
            suggestion="Use `get_<field>()` (required accessor) instead of `get_optional_<field>().unwrap_or(...)`.",
            context="Required fields should fail explicitly if missing, not silently use defaults.",
            exclude_test_files=True,
            exclude_patterns=[r"^\s*//", r"^\s*\*"],
        ),
    ]
