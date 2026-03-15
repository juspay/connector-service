#!/usr/bin/env python3
"""Bulk test script: runs pr-review against ALL merged PRs.

Outputs a comprehensive report with:
- Per-PR score, findings count, file types touched
- Error tracking (any crash = bug to fix)
- Coverage analysis (which rules fired, which never fired)
- Aggregated statistics

Usage:
    python bulk_test.py                    # Test all merged PRs
    python bulk_test.py --limit 50         # Test first 50
    python bulk_test.py --from-pr 600      # Test PRs >= 600
    python bulk_test.py --report report.json  # Save full report
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

# Add pr_review to path
sys.path.insert(0, str(Path(__file__).parent))

from pr_review.analyzer import Analyzer
from pr_review.config import Config
from pr_review.diff_parser import parse_diff
from pr_review.file_classifier import FileType, classify_files
from pr_review.github import fetch_pr_diff, fetch_pr_metadata, parse_pr_url
from pr_review.learner import default_learned_data_path, load_learned_data
from pr_review.rules import get_all_rules
from pr_review.rules.base import Severity


OWNER = "juspay"
REPO = "connector-service"


def get_merged_pr_numbers() -> list[int]:
    """Fetch all merged PR numbers via gh CLI."""
    result = subprocess.run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            f"{OWNER}/{REPO}",
            "--state",
            "merged",
            "--limit",
            "1000",
            "--json",
            "number",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh pr list failed: {result.stderr}")
    return sorted(p["number"] for p in json.loads(result.stdout))


def review_pr(number: int, rules, config: Config, repo_root: str) -> dict:
    """Run review on a single PR. Returns result dict."""
    entry = {
        "pr": number,
        "score": None,
        "status": None,
        "findings": 0,
        "criticals": 0,
        "warnings": 0,
        "suggestions": 0,
        "files": 0,
        "file_types": [],
        "rules_fired": [],
        "error": None,
        "title": "",
        "time_ms": 0,
        "skipped": False,
    }

    start = time.time()
    try:
        # Fetch metadata + diff
        metadata = fetch_pr_metadata(OWNER, REPO, number)
        entry["title"] = metadata.title

        try:
            diff_text = fetch_pr_diff(OWNER, REPO, number)
        except RuntimeError as e:
            if "too_large" in str(e) or "HTTP 406" in str(e):
                entry["score"] = -1
                entry["status"] = "SKIPPED (diff too large)"
                entry["skipped"] = True
                entry["time_ms"] = int((time.time() - start) * 1000)
                return entry
            raise

        if not diff_text.strip():
            entry["score"] = 100
            entry["status"] = "EMPTY"
            entry["time_ms"] = int((time.time() - start) * 1000)
            return entry

        # Run analysis
        analyzer = Analyzer(
            repo_root=repo_root,
            rules=rules,
            pr_title=metadata.title,
        )
        result = analyzer.analyze_diff(diff_text)

        # Apply config filters
        result.findings = [
            f for f in result.findings if not config.should_ignore_file(f.file_path)
        ]

        # Collect file types
        changed_files = parse_diff(diff_text)
        classified = classify_files(changed_files)
        file_types = list(set(cf.file_type.name for cf in classified))

        # Populate entry
        entry["score"] = result.quality_score
        entry["status"] = result.status
        entry["findings"] = len(result.findings)
        entry["criticals"] = sum(
            1 for f in result.findings if f.severity == Severity.CRITICAL
        )
        entry["warnings"] = sum(
            1 for f in result.findings if f.severity == Severity.WARNING
        )
        entry["suggestions"] = sum(
            1 for f in result.findings if f.severity == Severity.SUGGESTION
        )
        entry["files"] = len(changed_files)
        entry["file_types"] = file_types
        entry["rules_fired"] = list(set(f.rule_id for f in result.findings))

    except Exception as e:
        entry["error"] = f"{type(e).__name__}: {e}"
        entry["traceback"] = traceback.format_exc()

    entry["time_ms"] = int((time.time() - start) * 1000)
    return entry


def print_progress(current: int, total: int, entry: dict):
    """Print a single-line progress update."""
    if entry.get("skipped"):
        status = "SKP"
    elif entry["error"]:
        status = "ERR"
    else:
        status = f"{entry['score']:3d}"
    findings = entry["findings"]
    elapsed = entry["time_ms"]
    title = (entry["title"] or "???")[:50]
    print(
        f"  [{current:3d}/{total}] PR #{entry['pr']:4d}  "
        f"Score={status}  Findings={findings:2d}  "
        f"{elapsed:4d}ms  {title}"
    )


def print_report(results: list[dict]):
    """Print comprehensive summary report."""
    total = len(results)
    errors = [r for r in results if r["error"]]
    skipped = [r for r in results if r.get("skipped")]
    reviewed = [r for r in results if r["error"] is None and not r.get("skipped")]
    scores = [r["score"] for r in reviewed if r["score"] is not None]

    print("\n" + "=" * 80)
    print("BULK TEST REPORT")
    print("=" * 80)

    # Overview
    print(f"\n--- Overview ---")
    print(f"  Total PRs tested:    {total}")
    print(f"  Successful reviews:  {len(reviewed)}")
    print(f"  Skipped (too large): {len(skipped)}")
    print(f"  Errors/crashes:      {len(errors)}")
    print(f"  Error rate:          {len(errors) / total * 100:.1f}%")

    if scores:
        avg_score = sum(scores) / len(scores)
        print(f"\n--- Score Distribution ---")
        print(f"  Average score:       {avg_score:.1f}")
        print(f"  Median score:        {sorted(scores)[len(scores) // 2]}")
        print(f"  Min score:           {min(scores)}")
        print(f"  Max score:           {max(scores)}")

        brackets = {
            "Excellent (95-100)": sum(1 for s in scores if s >= 95),
            "Good (80-94)": sum(1 for s in scores if 80 <= s < 95),
            "Pass (60-79)": sum(1 for s in scores if 60 <= s < 80),
            "Blocked (40-59)": sum(1 for s in scores if 40 <= s < 60),
            "Critical (0-39)": sum(1 for s in scores if s < 40),
        }
        for label, count in brackets.items():
            bar = "#" * (count * 40 // max(1, total))
            print(
                f"  {label:20s}: {count:3d} ({count / len(scores) * 100:5.1f}%)  {bar}"
            )

    # Findings distribution
    total_findings = sum(r["findings"] for r in reviewed)
    total_criticals = sum(r["criticals"] for r in reviewed)
    total_warnings = sum(r["warnings"] for r in reviewed)
    total_suggestions = sum(r["suggestions"] for r in reviewed)
    print(f"\n--- Findings ---")
    print(f"  Total findings:      {total_findings}")
    print(f"  Criticals:           {total_criticals}")
    print(f"  Warnings:            {total_warnings}")
    print(f"  Suggestions:         {total_suggestions}")
    print(f"  Avg per PR:          {total_findings / max(1, len(reviewed)):.1f}")

    zero_finding_prs = [r for r in reviewed if r["findings"] == 0]
    print(
        f"  PRs with 0 findings: {len(zero_finding_prs)} ({len(zero_finding_prs) / max(1, len(reviewed)) * 100:.1f}%)"
    )

    # Rule coverage
    all_rules_fired = Counter()
    for r in reviewed:
        for rule_id in r["rules_fired"]:
            all_rules_fired[rule_id] += 1

    print(f"\n--- Rule Coverage ---")
    print(f"  Rules that fired:    {len(all_rules_fired)}/63")

    # Get all rule IDs
    all_rule_ids = set()
    from pr_review.rules import get_all_rules as get_rules

    for rule in get_rules():
        all_rule_ids.add(rule.rule_id)

    never_fired = all_rule_ids - set(all_rules_fired.keys())
    if never_fired:
        print(f"  Never fired:         {sorted(never_fired)}")

    print(f"\n  Top 15 most common rules:")
    for rule_id, count in all_rules_fired.most_common(15):
        print(f"    {rule_id}: {count} PRs")

    # File type coverage
    all_file_types = Counter()
    for r in reviewed:
        for ft in r["file_types"]:
            all_file_types[ft] += 1

    print(f"\n--- File Type Coverage ---")
    for ft, count in all_file_types.most_common():
        print(f"  {ft:25s}: {count:3d} PRs")

    # Timing
    times = [r["time_ms"] for r in results]
    print(f"\n--- Performance ---")
    print(f"  Avg time per PR:     {sum(times) / max(1, len(times)):.0f}ms")
    print(f"  Max time:            {max(times)}ms")
    print(f"  Total time:          {sum(times) / 1000:.1f}s")

    # Errors
    if errors:
        print(f"\n--- ERRORS ({len(errors)}) ---")
        for e in errors:
            print(f"  PR #{e['pr']}: {e['error']}")
            if e.get("traceback"):
                for line in e["traceback"].strip().split("\n")[-3:]:
                    print(f"    {line}")

    # Skipped PRs
    if skipped:
        print(f"\n--- SKIPPED ({len(skipped)}) ---")
        for s in skipped:
            print(f"  PR #{s['pr']}: {s['title'][:60]} (diff too large for GitHub API)")

    # Zero-finding PRs with file types (to spot coverage gaps)
    print(f"\n--- Zero-Finding PRs by File Type ---")
    zero_by_type = Counter()
    for r in zero_finding_prs:
        for ft in r["file_types"]:
            zero_by_type[ft] += 1
    for ft, count in zero_by_type.most_common():
        total_for_type = all_file_types.get(ft, 0)
        print(f"  {ft:25s}: {count}/{total_for_type} PRs had 0 findings")

    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Bulk test pr-review against all merged PRs"
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="Max number of PRs to test"
    )
    parser.add_argument(
        "--from-pr", type=int, default=None, help="Start from this PR number"
    )
    parser.add_argument("--to-pr", type=int, default=None, help="End at this PR number")
    parser.add_argument(
        "--report", type=str, default=None, help="Save JSON report to file"
    )
    args = parser.parse_args()

    print("Fetching merged PR list...")
    pr_numbers = get_merged_pr_numbers()
    print(f"Found {len(pr_numbers)} merged PRs")

    if args.from_pr:
        pr_numbers = [n for n in pr_numbers if n >= args.from_pr]
    if args.to_pr:
        pr_numbers = [n for n in pr_numbers if n <= args.to_pr]
    if args.limit:
        pr_numbers = pr_numbers[: args.limit]

    print(f"Testing {len(pr_numbers)} PRs (#{pr_numbers[0]} - #{pr_numbers[-1]})")

    # Setup once
    repo_root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    config_path = Path(repo_root) / "tools" / "pr-review" / "pr-review.toml"
    config = Config.load(str(config_path)) if config_path.exists() else Config()

    learned_path = default_learned_data_path(repo_root)
    learned_data = load_learned_data(learned_path)

    rules = get_all_rules(learned_data=learned_data)
    rules = config.apply_to_rules(rules)

    # Run reviews
    results = []
    total = len(pr_numbers)

    print(f"\nStarting bulk review...\n")
    overall_start = time.time()

    for i, pr_num in enumerate(pr_numbers, 1):
        entry = review_pr(pr_num, rules, config, repo_root)
        results.append(entry)
        print_progress(i, total, entry)

    overall_elapsed = time.time() - overall_start
    print(f"\nCompleted in {overall_elapsed:.1f}s")

    # Report
    print_report(results)

    # Save JSON report
    if args.report:
        # Strip traceback for JSON output
        clean = []
        for r in results:
            c = dict(r)
            c.pop("traceback", None)
            clean.append(c)
        with open(args.report, "w") as f:
            json.dump(clean, f, indent=2)
        print(f"\nJSON report saved to {args.report}")

    # Exit with error code if any crashes (skipped PRs are NOT errors)
    errors = [r for r in results if r["error"]]
    skipped = [r for r in results if r.get("skipped")]
    if errors:
        print(f"\n!! {len(errors)} PR(s) caused errors — these need fixing!")
        sys.exit(1)
    else:
        msg = f"\n0 errors — all {len(results)} PRs reviewed successfully."
        if skipped:
            msg += f" ({len(skipped)} skipped due to GitHub API diff size limits)"
        print(msg)
        sys.exit(0)


if __name__ == "__main__":
    main()
