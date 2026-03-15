"""CLI entry point for the PR review agent."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from pr_review.analyzer import Analyzer, AnalysisResult
from pr_review.config import Config
from pr_review.reporter import (
    generate_terminal_report,
    generate_markdown_report,
    generate_json_report,
)
from pr_review.rules import get_all_rules


def _find_repo_root() -> str:
    """Find the git repository root from the current directory."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        click.echo("Error: git command timed out.", err=True)
        sys.exit(1)
    if result.returncode != 0:
        click.echo("Error: not inside a git repository.", err=True)
        sys.exit(1)
    return result.stdout.strip()


def _render_rich_report(result: AnalysisResult) -> None:
    """Render the report using rich for better terminal formatting."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich import box

        console = Console()

        # Header
        score = result.quality_score
        status = result.status

        if score >= 80:
            score_style = "bold green"
        elif score >= 60:
            score_style = "bold yellow"
        else:
            score_style = "bold red"

        header_text = Text()
        header_text.append("Quality Score: ", style="bold")
        header_text.append(f"{score}/100", style=score_style)
        header_text.append("  |  Status: ", style="bold")
        header_text.append(status, style=score_style)

        console.print()
        console.print(
            Panel(header_text, title="PR Review - connector-service", box=box.DOUBLE)
        )

        # Summary table
        summary = Table(title="Summary", box=box.SIMPLE)
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", justify="right")
        summary.add_row("Files analyzed", str(result.files_analyzed))
        summary.add_row("Rules applied", str(result.rules_applied))
        summary.add_row("Total findings", str(result.total_findings))
        if result.connector_names:
            summary.add_row("Connectors", ", ".join(sorted(result.connector_names)))
        console.print(summary)

        # Issue counts
        issues = Table(title="Issue Breakdown", box=box.SIMPLE)
        issues.add_column("Severity", style="bold")
        issues.add_column("Count", justify="right")
        issues.add_column("Score Impact", justify="right")
        issues.add_row(
            "[red]Critical[/red]",
            str(result.critical_count),
            f"-{result.critical_count * 20}",
        )
        issues.add_row(
            "[yellow]Warning[/yellow]",
            str(result.warning_count),
            f"-{result.warning_count * 5}",
        )
        issues.add_row(
            "[blue]Suggestion[/blue]",
            str(result.suggestion_count),
            f"-{result.suggestion_count * 1}",
        )
        console.print(issues)

        if not result.findings:
            console.print("[green]No issues found. Great job![/green]")
            console.print()
            return

        # Findings grouped by severity
        from pr_review.rules.base import Severity

        severity_styles = {
            Severity.CRITICAL: ("red", "!!"),
            Severity.WARNING: ("yellow", " !"),
            Severity.SUGGESTION: ("blue", " *"),
        }

        by_severity = result.findings_by_severity()

        for severity in (Severity.CRITICAL, Severity.WARNING, Severity.SUGGESTION):
            findings = by_severity[severity]
            if not findings:
                continue

            style, icon = severity_styles[severity]
            console.print()
            console.rule(
                f"[{style}]{icon} {severity.value.upper()} ({len(findings)})[/{style}]"
            )
            console.print()

            for finding in findings:
                # Compact finding display
                console.print(
                    f"  [{style}][{finding.rule_id}][/{style}] {finding.rule_name}"
                )
                console.print(f"  [dim]{finding.location}[/dim]")
                console.print(f"  {finding.message}")
                if finding.line_content:
                    console.print(
                        f"  [dim]Code:[/dim] [italic]{finding.line_content}[/italic]"
                    )
                if finding.suggestion:
                    console.print(f"  [green]Fix:[/green] {finding.suggestion}")
                console.print()

        # Category breakdown
        console.print()
        cat_table = Table(title="Findings by Category", box=box.SIMPLE)
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Count", justify="right")
        by_category = result.findings_by_category()
        from pr_review.rules.base import Category

        for category in Category:
            count = len(by_category[category])
            if count > 0:
                cat_table.add_row(category.value, str(count))
        console.print(cat_table)
        console.print()

    except ImportError:
        # Fallback to plain text if rich is not available
        click.echo(generate_terminal_report(result))


def _warn_if_stale(learned_data: dict, max_age_days: int = 7) -> None:
    """Warn if learned_data.json is older than max_age_days."""
    import time

    generated_at = learned_data.get("generated_at")
    if not generated_at:
        return

    try:
        gen_time = time.mktime(time.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ"))
        age_days = (time.time() - gen_time) / 86400
        if age_days > max_age_days:
            click.echo(
                f"Warning: learned_data.json is {int(age_days)} days old. "
                f"Run `python -m pr_review learn` to refresh.",
                err=True,
            )
    except (ValueError, OverflowError):
        pass


class DefaultGroup(click.Group):
    """A Click group that falls back to a default command ('review')."""

    def __init__(self, *args, default_cmd: str = "review", **kwargs):
        super().__init__(*args, **kwargs)
        self.default_cmd = default_cmd

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        # Don't redirect if --help or -h is the first arg
        if args and args[0] in ("--help", "-h"):
            return super().parse_args(ctx, args)
        # If the first arg is not a known command, insert the default command
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = [self.default_cmd] + args
        elif not args or args[0].startswith("-"):
            args = [self.default_cmd] + args
        return super().parse_args(ctx, args)


@click.group(cls=DefaultGroup)
def cli() -> None:
    """PR Review Agent for connector-service.

    Performs rule-based static analysis of code changes against
    connector-service best practices and coding conventions.

    \b
    Subcommands:
      review  (default) Review local branch changes
      pr      Review a GitHub PR and post comments
      learn   Scan codebase and update rule data
    """


@cli.command()
@click.option(
    "--base",
    default="main",
    help="Base branch to diff against (default: main).",
    show_default=True,
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "markdown", "json"]),
    default="terminal",
    help="Output format.",
    show_default=True,
)
@click.option(
    "--fail-under",
    type=int,
    default=None,
    help="Exit with code 1 if quality score is below this threshold (default: from config or 60).",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "warning", "suggestion"]),
    default="suggestion",
    help="Minimum severity level to report.",
    show_default=True,
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to config file (default: tools/pr-review/pr-review.toml).",
)
@click.option(
    "--repo-root",
    type=click.Path(exists=True),
    default=None,
    help="Path to repository root (default: auto-detect from git).",
)
@click.option(
    "--pr-title",
    default=None,
    help="PR title to check (default: last commit message).",
)
@click.option(
    "--diff-file",
    type=click.Path(exists=True),
    default=None,
    help="Read diff from a file instead of running git diff.",
)
@click.option(
    "--no-learn",
    is_flag=True,
    default=False,
    help="Skip loading learned data (use hardcoded defaults).",
)
def review(
    base: str,
    output_format: str,
    fail_under: int | None,
    min_severity: str,
    config_path: str | None,
    repo_root: str | None,
    pr_title: str | None,
    diff_file: str | None,
    no_learn: bool,
) -> None:
    """Review code changes against connector-service conventions.

    Run from the connector-service repository root:

        python -m pr_review review --base main

    Or with a diff file:

        git diff main...HEAD > changes.diff
        python -m pr_review review --diff-file changes.diff

    This is the default command when no subcommand is specified.
    """
    # Resolve repo root
    if repo_root is None:
        repo_root = _find_repo_root()

    # Load config
    if config_path is None:
        default_config = Path(repo_root) / "tools" / "pr-review" / "pr-review.toml"
        if default_config.exists():
            config_path = str(default_config)

    config = Config.load(config_path) if config_path else Config()

    # Override fail_under from CLI if provided
    threshold = fail_under if fail_under is not None else config.fail_under

    # Load learned data
    learned_data = None
    if not no_learn:
        from pr_review.learner import load_learned_data, default_learned_data_path

        learned_path = default_learned_data_path(repo_root)
        learned_data = load_learned_data(learned_path)
        if learned_data:
            _warn_if_stale(learned_data)
        else:
            click.echo(
                "Note: No learned_data.json found. Run `python -m pr_review learn` to improve analysis.",
                err=True,
            )

    # Load and configure rules
    rules = get_all_rules(learned_data=learned_data)
    rules = config.apply_to_rules(rules)

    # Create analyzer
    analyzer = Analyzer(
        repo_root=repo_root,
        rules=rules,
        pr_title=pr_title,
    )

    # Run analysis
    if diff_file:
        with open(diff_file, "r") as f:
            diff_text = f.read()
        result = analyzer.analyze_diff(diff_text)
    else:
        try:
            result = analyzer.analyze_branch(base)
        except RuntimeError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    # Filter findings by minimum severity
    severity_order = {
        "critical": 0,
        "warning": 1,
        "suggestion": 2,
    }
    from pr_review.rules.base import Severity

    min_sev_val = severity_order[min_severity]
    result.findings = [
        f for f in result.findings if severity_order[f.severity.value] <= min_sev_val
    ]

    # Filter out ignored files
    result.findings = [
        f for f in result.findings if not config.should_ignore_file(f.file_path)
    ]

    # Generate output
    if output_format == "terminal":
        _render_rich_report(result)
    elif output_format == "markdown":
        click.echo(generate_markdown_report(result))
    elif output_format == "json":
        click.echo(generate_json_report(result))

    # Exit with appropriate code
    if result.quality_score < threshold:
        sys.exit(1)


@cli.command()
@click.argument("url")
@click.option(
    "--no-learn",
    is_flag=True,
    default=False,
    help="Skip loading learned data (use hardcoded defaults).",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "warning", "suggestion"]),
    default="suggestion",
    help="Minimum severity level to report.",
    show_default=True,
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show findings locally but skip posting to GitHub.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to config file (default: tools/pr-review/pr-review.toml).",
)
def pr(
    url: str,
    no_learn: bool,
    min_severity: str,
    dry_run: bool,
    config_path: str | None,
) -> None:
    """Review a GitHub PR and optionally post findings as comments.

    Fetches the PR diff from GitHub, runs the review locally, shows
    findings in the terminal, then lets you interactively select which
    findings to post as line-level review comments on the PR.

    URL can be a full GitHub URL or shorthand:

    \b
        python -m pr_review pr https://github.com/owner/repo/pull/123
        python -m pr_review pr owner/repo#123
        python -m pr_review pr owner/repo#123 --dry-run
    """
    from pr_review.github import (
        parse_pr_url,
        check_gh_available,
        fetch_pr_diff,
        fetch_pr_metadata,
        build_diff_line_set,
        classify_findings_for_review,
        build_review_body,
        post_review as gh_post_review,
    )

    # 1. Check gh is available
    if not check_gh_available():
        click.echo(
            "Error: `gh` CLI is not installed or not authenticated.\n"
            "Install: https://cli.github.com\n"
            "Auth:    gh auth login",
            err=True,
        )
        sys.exit(1)

    # 2. Parse URL
    try:
        owner, repo, number = parse_pr_url(url)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Reviewing PR #{number} on {owner}/{repo}...")

    # 3. Fetch diff + metadata
    try:
        metadata = fetch_pr_metadata(owner, repo, number)
        diff_text = fetch_pr_diff(owner, repo, number)
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if not diff_text.strip():
        click.echo("PR has no changes.")
        return

    click.echo(f"PR: {metadata.title}")
    click.echo(f"Branch: {metadata.head_branch} -> {metadata.base_branch}")
    click.echo()

    # 4. Resolve repo root and load config
    try:
        repo_root = _find_repo_root()
    except SystemExit:
        repo_root = os.getcwd()

    if config_path is None:
        default_config = Path(repo_root) / "tools" / "pr-review" / "pr-review.toml"
        if default_config.exists():
            config_path = str(default_config)

    config = Config.load(config_path) if config_path else Config()

    # 5. Load learned data
    learned_data = None
    if not no_learn:
        from pr_review.learner import load_learned_data, default_learned_data_path

        learned_path = default_learned_data_path(repo_root)
        learned_data = load_learned_data(learned_path)

    # 6. Load rules, apply config, run analysis
    rules = get_all_rules(learned_data=learned_data)
    rules = config.apply_to_rules(rules)

    analyzer = Analyzer(
        repo_root=repo_root,
        rules=rules,
        pr_title=metadata.title,
    )
    result = analyzer.analyze_diff(diff_text)

    # 7. Filter by min severity and ignored files
    severity_order = {"critical": 0, "warning": 1, "suggestion": 2}
    from pr_review.rules.base import Severity

    min_sev_val = severity_order[min_severity]
    result.findings = [
        f for f in result.findings if severity_order[f.severity.value] <= min_sev_val
    ]
    result.findings = [
        f for f in result.findings if not config.should_ignore_file(f.file_path)
    ]

    # 8. Display findings in terminal
    _render_rich_report(result)

    if not result.findings:
        click.echo("No findings to post.")
        return

    if dry_run:
        click.echo("Dry run -- skipping GitHub posting.")
        return

    # 9. Classify findings for review posting
    diff_lines = build_diff_line_set(diff_text)
    postable, body_only = classify_findings_for_review(result.findings, diff_lines)

    if not postable:
        click.echo("No findings can be posted as line comments (all are PR-level).")
        if body_only:
            click.echo(
                f"{len(body_only)} PR-level finding(s) will be in the review body."
            )
            if not click.confirm("Post review summary?"):
                return
            review_body = build_review_body(result, 0, 0)
            review_body = _append_body_findings(review_body, body_only)
            try:
                review_url = gh_post_review(owner, repo, number, review_body, [])
                click.echo(f"Review posted: {review_url}")
            except RuntimeError as e:
                click.echo(f"Error posting review: {e}", err=True)
                sys.exit(1)
        return

    # 10. Interactive selection
    _show_postable_findings(postable, body_only)

    selection = click.prompt(
        "Select findings to post (numbers e.g. '1,3,5', range '1-3', 'all', or 'none')",
        default="none",
    )

    selected_indices = _parse_selection(selection, len(postable))
    if selected_indices is None:
        click.echo("No findings selected. Exiting.")
        return

    # 11. Build and post review
    selected_comments = [postable[i][1] for i in selected_indices]
    review_body = build_review_body(result, len(selected_comments), len(postable))
    review_body = _append_body_findings(review_body, body_only)

    click.echo()
    click.echo(f"Posting review with {len(selected_comments)} comment(s)...")

    try:
        review_url = gh_post_review(owner, repo, number, review_body, selected_comments)
        click.echo(f"Review posted: {review_url}")
    except RuntimeError as e:
        click.echo(f"Error posting review: {e}", err=True)
        sys.exit(1)


def _show_postable_findings(
    postable: list[tuple],
    body_only: list,
) -> None:
    """Display the numbered list of postable findings for interactive selection."""
    from pr_review.rules.base import Severity

    click.echo()
    click.echo("=" * 60)
    click.echo("Findings available to post as comments:")
    click.echo()

    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.SUGGESTION: "blue",
    }

    for i, (finding, comment) in enumerate(postable, 1):
        comment_type = "LINE" if "line" in comment else "FILE"
        sev = finding.severity.value.upper()
        styled_sev = click.style(sev, fg=severity_colors.get(finding.severity))
        loc = finding.location
        click.echo(f"  [{i:2d}] {finding.rule_id} | {styled_sev} | {loc}")
        click.echo(f"       {finding.message}  [{comment_type}]")

    if body_only:
        click.echo()
        click.echo("  PR-level findings (included in review body only):")
        for finding in body_only:
            click.echo(f"   *   {finding.rule_id} | {finding.message}")

    click.echo()
    click.echo(f"Total: {len(postable)} postable, {len(body_only)} body-only")
    click.echo()


def _parse_selection(selection: str, max_count: int) -> list[int] | None:
    """Parse user selection input into a list of 0-based indices.

    Returns:
        List of unique 0-based indices, or None if 'none' was selected.
    """
    selection = selection.strip().lower()

    if selection == "none":
        return None

    if selection == "all":
        return list(range(max_count))

    try:
        indices: list[int] = []
        for part in selection.split(","):
            part = part.strip()
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start = int(start_s.strip())
                end = int(end_s.strip())
                indices.extend(range(start - 1, end))
            else:
                indices.append(int(part) - 1)

        # Validate range
        for idx in indices:
            if idx < 0 or idx >= max_count:
                click.echo(
                    f"Error: {idx + 1} is out of range (1-{max_count}).",
                    err=True,
                )
                sys.exit(1)

        # Deduplicate while preserving order
        seen: set[int] = set()
        unique: list[int] = []
        for idx in indices:
            if idx not in seen:
                seen.add(idx)
                unique.append(idx)
        return unique

    except ValueError:
        click.echo(
            "Error: invalid selection. Use numbers, ranges, 'all', or 'none'.",
            err=True,
        )
        sys.exit(1)


def _append_body_findings(review_body: str, body_only: list) -> str:
    """Append PR-level findings to the review body text."""
    if not body_only:
        return review_body

    parts = [review_body, "", "### PR-Level Findings", ""]
    for finding in body_only:
        parts.append(f"- **[{finding.rule_id}]** {finding.message}")
        if finding.suggestion:
            parts.append(f"  - Fix: {finding.suggestion}")
    return "\n".join(parts)


@cli.command()
@click.option(
    "--repo-root",
    type=click.Path(exists=True),
    default=None,
    help="Path to repository root (default: auto-detect from git).",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Output path for learned_data.json (default: tools/pr-review/learned_data.json).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress detailed output.",
)
def learn(
    repo_root: str | None,
    output: str | None,
    quiet: bool,
) -> None:
    """Scan the codebase and update learned rule data.

    This command scans the repository to extract patterns, conventions,
    and configuration that the review rules use. The extracted data is
    saved to learned_data.json and loaded automatically during review.

    Run this after significant codebase changes:

        python -m pr_review learn

    The learned data includes:
      - Clippy lint levels from Cargo.toml
      - Flow structs and trait mappings
      - ConnectorCommon method signatures
      - Known connector names
      - AttemptStatus enum variants
      - Sensitive field patterns from code
      - Error response struct patterns
      - Conventional commit configuration
      - Proto conventions (package, services, SecretString)
      - Composite service patterns
    """
    from pr_review.learner import (
        learn as run_learner,
        save_learned_data,
        default_learned_data_path,
    )

    # Resolve repo root
    if repo_root is None:
        repo_root = _find_repo_root()

    # Resolve output path
    if output is None:
        output = default_learned_data_path(repo_root)

    if not quiet:
        click.echo(f"Scanning repository: {repo_root}")
        click.echo()

    # Run the learner
    data = run_learner(repo_root)

    # Save
    save_learned_data(data, output)

    if not quiet:
        click.echo("Learned data summary:")
        click.echo(f"  Clippy lints:         {len(data['lints']['clippy'])}")
        click.echo(f"  Rust lints:           {len(data['lints']['rust'])}")
        click.echo(f"  Flow structs:         {len(data['flows']['flow_structs'])}")
        click.echo(f"  Flow-trait mappings:  {len(data['flows']['flow_trait_map'])}")
        click.echo(
            f"  ConnectorCommon methods: {len(data['connector_common_methods'])}"
        )
        click.echo(f"  Known connectors:     {len(data['known_connectors'])}")
        click.echo(
            f"  AttemptStatus variants: {len(data['attempt_status']['variants'])}"
        )
        click.echo(
            f"  Sensitive field names: {len(data['sensitive_fields_from_code'])}"
        )
        click.echo(f"  Error response structs: {len(data['error_response_patterns'])}")
        click.echo(
            f"  Commit types:         {len(data['commit_config']['commit_types'])}"
        )
        proto = data.get("proto_conventions", {})
        click.echo(f"  Proto package:        {proto.get('package_name', 'N/A')}")
        click.echo(f"  Proto services:       {len(proto.get('service_names', []))}")
        click.echo(
            f"  Proto SecretString fields: {len(proto.get('secret_string_fields', []))}"
        )
        composite = data.get("composite_service", {})
        click.echo(f"  Composite requests:   {len(composite.get('request_types', []))}")
        click.echo(
            f"  Composite methods:    {len(composite.get('process_methods', []))}"
        )
        click.echo()
        click.echo(f"Saved to: {output}")
        click.echo(f"Generated at: {data['generated_at']}")
    else:
        click.echo(output)


# Keep backward compatibility: the old `main` function delegates to the group
def main() -> None:
    """Entry point for python -m pr_review."""
    cli()


if __name__ == "__main__":
    main()
