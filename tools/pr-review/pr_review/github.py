"""GitHub interaction via the `gh` CLI.

Provides functions to fetch PR diffs and metadata, format findings as
review comments, and post reviews with line-level comments — all through
the GitHub CLI (no direct API tokens needed).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pr_review.analyzer import AnalysisResult

from pr_review.rules.base import Finding, Severity


@dataclass
class PRMetadata:
    """Metadata about a pull request."""

    owner: str
    repo: str
    number: int
    title: str
    base_branch: str
    head_branch: str
    url: str


def parse_pr_url(url: str) -> tuple[str, str, int]:
    """Parse a GitHub PR URL into (owner, repo, number).

    Supports:
        https://github.com/owner/repo/pull/123
        http://github.com/owner/repo/pull/123
        github.com/owner/repo/pull/123
        owner/repo#123

    Returns:
        Tuple of (owner, repo, pr_number).

    Raises:
        ValueError: If the URL format is not recognized.
    """
    cleaned = url.strip()

    # Full URL: https://github.com/owner/repo/pull/123
    m = re.match(
        r"(?:https?://)?github\.com/([^/]+)/([^/]+)/pull/(\d+)",
        cleaned,
    )
    if m:
        return m.group(1), m.group(2), int(m.group(3))

    # Short format: owner/repo#123
    m = re.match(r"^([^/\s]+)/([^#\s]+)#(\d+)$", cleaned)
    if m:
        return m.group(1), m.group(2), int(m.group(3))

    raise ValueError(
        f"Cannot parse PR URL: {url}\n"
        "Expected: https://github.com/owner/repo/pull/123 or owner/repo#123"
    )


def check_gh_available() -> bool:
    """Check if `gh` CLI is installed and authenticated.

    Returns:
        True if gh is available and authenticated.
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def fetch_pr_diff(owner: str, repo: str, number: int) -> str:
    """Fetch the unified diff for a PR via ``gh pr diff``.

    Returns:
        Raw unified diff text.

    Raises:
        RuntimeError: If the gh command fails.
    """
    result = subprocess.run(
        ["gh", "pr", "diff", str(number), "-R", f"{owner}/{repo}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to fetch PR diff: {result.stderr.strip()}")
    return result.stdout


def fetch_pr_metadata(owner: str, repo: str, number: int) -> PRMetadata:
    """Fetch PR title, branches, and URL via ``gh pr view``.

    Returns:
        PRMetadata with title, branches, and URL.

    Raises:
        RuntimeError: If the gh command fails.
    """
    result = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            str(number),
            "-R",
            f"{owner}/{repo}",
            "--json",
            "title,baseRefName,headRefName,url",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to fetch PR metadata: {result.stderr.strip()}")

    data = json.loads(result.stdout)
    return PRMetadata(
        owner=owner,
        repo=repo,
        number=number,
        title=data["title"],
        base_branch=data["baseRefName"],
        head_branch=data["headRefName"],
        url=data["url"],
    )


def build_diff_line_set(diff_text: str) -> set[tuple[str, int]]:
    """Build a set of (file_path, line_number) for all added lines in the diff.

    Used to determine which findings can be posted as line-level comments
    (only lines that appear as additions in the diff are eligible).

    Returns:
        Set of (file_path, line_number) tuples.
    """
    from pr_review.diff_parser import parse_diff

    result: set[tuple[str, int]] = set()
    for cf in parse_diff(diff_text):
        for line in cf.added_lines:
            if line.line_number > 0:
                result.add((cf.path, line.line_number))
    return result


def format_finding_as_comment(finding: Finding) -> str:
    """Format a Finding as a markdown comment body for GitHub.

    Returns:
        Markdown-formatted comment text.
    """
    severity_label = {
        Severity.CRITICAL: "Critical",
        Severity.WARNING: "Warning",
        Severity.SUGGESTION: "Suggestion",
    }

    parts = [
        f"**[{finding.rule_id}] {finding.rule_name}** "
        f"({severity_label[finding.severity]})",
        "",
        finding.message,
    ]

    if finding.suggestion:
        parts.extend(["", f"**Fix:** {finding.suggestion}"])

    if finding.context:
        parts.extend(["", f"*{finding.context}*"])

    return "\n".join(parts)


def build_review_body(
    result: AnalysisResult,
    posted_count: int,
    total_postable: int,
) -> str:
    """Build the markdown review body (summary) for a GitHub PR review.

    Args:
        result: The analysis result.
        posted_count: Number of findings posted as line comments.
        total_postable: Total number of postable findings.

    Returns:
        Markdown review body text.
    """
    score = result.quality_score
    status = result.status

    # Extract label from status like "PASS (Good)" -> "Good"
    if "(" in status:
        label = status.split("(")[-1].rstrip(")")
    else:
        label = status

    lines = [
        "## PR Review -- connector-service",
        "",
        f"**Quality Score:** {score}/100 ({label})",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {result.critical_count} |",
        f"| Warning | {result.warning_count} |",
        f"| Suggestion | {result.suggestion_count} |",
    ]

    if posted_count > 0:
        lines.extend(
            [
                "",
                f"*Posted {posted_count} of {total_postable} findings as line comments.*",
            ]
        )
    elif total_postable > 0:
        lines.extend(
            [
                "",
                f"*{total_postable} findings available (none selected for posting).*",
            ]
        )

    return "\n".join(lines)


def classify_findings_for_review(
    findings: list[Finding],
    diff_lines: set[tuple[str, int]],
) -> tuple[list[tuple[Finding, dict]], list[Finding]]:
    """Classify findings into postable comments and body-only findings.

    Args:
        findings: All findings from the analysis.
        diff_lines: Set of (file_path, line_number) from the diff.

    Returns:
        Tuple of:
        - postable: List of (Finding, comment_dict) pairs that can be posted
          as line-level or file-level comments on the PR.
        - body_only: PR-level findings included in the review body only.
    """
    postable: list[tuple[Finding, dict]] = []
    body_only: list[Finding] = []

    for finding in findings:
        # PR-level findings (PQ-* rules or no file path)
        if finding.rule_id.startswith("PQ-") or not finding.file_path:
            body_only.append(finding)
            continue

        # Finding on an added line in the diff -> line-level comment
        if (
            finding.line_number > 0
            and (finding.file_path, finding.line_number) in diff_lines
        ):
            comment = {
                "path": finding.file_path,
                "line": finding.line_number,
                "side": "RIGHT",
                "body": format_finding_as_comment(finding),
            }
            postable.append((finding, comment))
        elif finding.file_path:
            # File in diff but line not on an added line -> file-level comment
            comment = {
                "path": finding.file_path,
                "body": format_finding_as_comment(finding),
                "subject_type": "file",
            }
            postable.append((finding, comment))

    return postable, body_only


def post_review(
    owner: str,
    repo: str,
    number: int,
    body: str,
    comments: list[dict],
) -> str:
    """Post a review with line-level comments via ``gh api``.

    Uses ``event: COMMENT`` (non-blocking, does not approve or request
    changes). Comments are grouped into a single review.

    Args:
        owner: Repository owner.
        repo: Repository name.
        number: PR number.
        body: Review body text (summary).
        comments: List of comment dicts with keys: path, body, and
            optionally line, side, subject_type.

    Returns:
        URL of the created review.

    Raises:
        RuntimeError: If the API call fails.
    """
    payload: dict = {
        "event": "COMMENT",
        "body": body,
    }

    if comments:
        payload["comments"] = comments

    # Write payload to a temp file to avoid shell escaping issues
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
    ) as f:
        json.dump(payload, f)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{owner}/{repo}/pulls/{number}/reviews",
                "-X",
                "POST",
                "--input",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        os.unlink(tmp_path)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to post review: {result.stderr.strip()}")

    response = json.loads(result.stdout)
    return response.get("html_url", "")
