"""
Incremental indexing support.

Provides git-based change detection to enable incremental re-indexing
of only modified files.
"""

import subprocess
from pathlib import Path
from typing import List, Optional


def get_current_commit(repo_path: str) -> Optional[str]:
    """Get the current HEAD commit SHA."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_changed_rs_files(repo_path: str, since_sha: str) -> List[str]:
    """Get list of added/changed/modified/renamed .rs files since a commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", since_sha, "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        files = result.stdout.strip().split("\n")
        return [f for f in files if f.endswith(".rs") and f]
    except subprocess.CalledProcessError:
        return []


def get_deleted_rs_files(repo_path: str, since_sha: str) -> List[str]:
    """Get list of deleted .rs files since a commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=D", since_sha, "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        files = result.stdout.strip().split("\n")
        return [f for f in files if f.endswith(".rs") and f]
    except subprocess.CalledProcessError:
        return []


def get_all_rs_files(repo_path: str, crates_dir: str = "crates") -> List[str]:
    """Get all .rs files in the crates directory."""
    crates_path = Path(repo_path) / crates_dir
    if not crates_path.exists():
        return []
    return [str(p) for p in crates_path.rglob("*.rs")]


def should_full_reindex(changed_count: int, total_count: int, threshold: float = 0.3) -> bool:
    """Determine if a full reindex is needed based on change ratio."""
    if total_count == 0:
        return True
    return (changed_count / total_count) >= threshold
