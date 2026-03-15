"""Reporter: generates human-readable output from analysis results."""

from __future__ import annotations

from pr_review.analyzer import AnalysisResult
from pr_review.rules.base import Finding, Severity, Category


def generate_terminal_report(result: AnalysisResult) -> str:
    """Generate a colored terminal report.

    Uses ANSI escape codes for color. The `rich` library will be used
    in the CLI layer for better formatting; this function produces
    a plain-text-with-ANSI version for direct printing.
    """
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append("=" * 72)
    lines.append("  PR REVIEW REPORT - connector-service")
    lines.append("=" * 72)
    lines.append("")

    # Score
    score = result.quality_score
    status = result.status
    lines.append(f"  Quality Score: {score}/100  |  Status: {status}")
    lines.append("")

    # Summary
    lines.append(f"  Files analyzed: {result.files_analyzed}")
    lines.append(f"  Rules applied:  {result.rules_applied}")
    lines.append(f"  Total findings: {result.total_findings}")
    if result.connector_names:
        lines.append(f"  Connectors:     {', '.join(sorted(result.connector_names))}")
    lines.append("")

    # Issue counts
    lines.append("  Issue Summary:")
    lines.append(
        f"    !! Critical:   {result.critical_count:3d}  (x{Severity.CRITICAL.score_penalty} = -{result.critical_count * Severity.CRITICAL.score_penalty})"
    )
    lines.append(
        f"     ! Warning:    {result.warning_count:3d}  (x{Severity.WARNING.score_penalty} = -{result.warning_count * Severity.WARNING.score_penalty})"
    )
    lines.append(
        f"     * Suggestion: {result.suggestion_count:3d}  (x{Severity.SUGGESTION.score_penalty} = -{result.suggestion_count * Severity.SUGGESTION.score_penalty})"
    )
    lines.append("")

    if not result.findings:
        lines.append("  No issues found. Great job!")
        lines.append("")
        lines.append("=" * 72)
        return "\n".join(lines)

    # Findings by severity
    by_severity = result.findings_by_severity()

    for severity in (Severity.CRITICAL, Severity.WARNING, Severity.SUGGESTION):
        findings = by_severity[severity]
        if not findings:
            continue

        lines.append("-" * 72)
        icon = severity.icon
        lines.append(f"  {icon} {severity.value.upper()} ISSUES ({len(findings)})")
        lines.append("-" * 72)

        for finding in findings:
            lines.append("")
            lines.append(f"  [{finding.rule_id}] {finding.rule_name}")
            lines.append(f"  Location: {finding.location}")
            lines.append(f"  {finding.message}")
            if finding.line_content:
                lines.append(f"  Code: {finding.line_content}")
            if finding.suggestion:
                lines.append(f"  Fix:  {finding.suggestion}")

        lines.append("")

    # Category breakdown
    lines.append("-" * 72)
    lines.append("  FINDINGS BY CATEGORY")
    lines.append("-" * 72)
    by_category = result.findings_by_category()
    for category in Category:
        count = len(by_category[category])
        if count > 0:
            lines.append(f"    {category.value:<25s} {count}")
    lines.append("")

    lines.append("=" * 72)
    return "\n".join(lines)


def generate_markdown_report(result: AnalysisResult) -> str:
    """Generate a markdown report suitable for PR comments."""
    lines: list[str] = []

    # Header
    score = result.quality_score
    status = result.status
    lines.append("# PR Review Report - connector-service")
    lines.append("")
    lines.append(f"**Quality Score: {score}/100** | **Status: {status}**")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Files analyzed | {result.files_analyzed} |")
    lines.append(f"| Rules applied | {result.rules_applied} |")
    lines.append(f"| Total findings | {result.total_findings} |")
    if result.connector_names:
        lines.append(f"| Connectors | {', '.join(sorted(result.connector_names))} |")
    lines.append("")

    # Issue summary
    lines.append("## Issue Summary")
    lines.append("")
    lines.append("| Severity | Count | Score Impact |")
    lines.append("|----------|-------|-------------|")
    lines.append(
        f"| Critical | {result.critical_count} | -{result.critical_count * Severity.CRITICAL.score_penalty} |"
    )
    lines.append(
        f"| Warning | {result.warning_count} | -{result.warning_count * Severity.WARNING.score_penalty} |"
    )
    lines.append(
        f"| Suggestion | {result.suggestion_count} | -{result.suggestion_count * Severity.SUGGESTION.score_penalty} |"
    )
    lines.append("")

    if not result.findings:
        lines.append("No issues found. Great job!")
        return "\n".join(lines)

    # Findings by severity
    by_severity = result.findings_by_severity()

    for severity in (Severity.CRITICAL, Severity.WARNING, Severity.SUGGESTION):
        findings = by_severity[severity]
        if not findings:
            continue

        lines.append(f"## {severity.value.title()} Issues ({len(findings)})")
        lines.append("")

        for finding in findings:
            lines.append(f"### [{finding.rule_id}] {finding.rule_name}")
            lines.append("")
            lines.append(f"**Location:** `{finding.location}`")
            lines.append("")
            lines.append(finding.message)
            lines.append("")
            if finding.line_content:
                lines.append("```rust")
                lines.append(finding.line_content)
                lines.append("```")
                lines.append("")
            if finding.suggestion:
                lines.append(f"**Fix:** {finding.suggestion}")
                lines.append("")
            if finding.context:
                lines.append(f"> {finding.context}")
                lines.append("")
            lines.append("---")
            lines.append("")

    # Category breakdown
    lines.append("## Findings by Category")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    by_category = result.findings_by_category()
    for category in Category:
        count = len(by_category[category])
        if count > 0:
            lines.append(f"| {category.value} | {count} |")
    lines.append("")

    return "\n".join(lines)


def generate_json_report(result: AnalysisResult) -> str:
    """Generate a JSON report for machine consumption."""
    import json

    data = {
        "quality_score": result.quality_score,
        "status": result.status,
        "is_passing": result.is_passing,
        "summary": {
            "files_analyzed": result.files_analyzed,
            "rules_applied": result.rules_applied,
            "total_findings": result.total_findings,
            "critical_count": result.critical_count,
            "warning_count": result.warning_count,
            "suggestion_count": result.suggestion_count,
            "connector_names": sorted(result.connector_names),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "category": f.category.value,
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "line_content": f.line_content,
                "suggestion": f.suggestion,
                "context": f.context,
                "location": f.location,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2)
