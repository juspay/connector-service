"""Parse git diff output into structured data."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DiffLine:
    """A single line from a diff hunk."""

    line_number: int  # Line number in the new file (0 if deleted line)
    content: str  # The actual line content (without +/- prefix)
    is_added: bool  # True if this line was added
    is_removed: bool  # True if this line was removed
    is_context: bool  # True if this is a context line (unchanged)

    @property
    def is_changed(self) -> bool:
        return self.is_added or self.is_removed


@dataclass
class DiffHunk:
    """A contiguous block of changes within a file."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str  # The @@ ... @@ line including any function context
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [ln for ln in self.lines if ln.is_added]

    @property
    def removed_lines(self) -> list[DiffLine]:
        return [ln for ln in self.lines if ln.is_removed]


@dataclass
class ChangedFile:
    """A file that was modified in the diff."""

    path: str  # Relative file path
    old_path: str | None  # Previous path if renamed
    is_new: bool  # True if file was newly created
    is_deleted: bool  # True if file was deleted
    is_renamed: bool  # True if file was renamed
    is_binary: bool  # True if binary file
    hunks: list[DiffHunk] = field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        """All added lines across all hunks."""
        result = []
        for hunk in self.hunks:
            result.extend(hunk.added_lines)
        return result

    @property
    def removed_lines(self) -> list[DiffLine]:
        """All removed lines across all hunks."""
        result = []
        for hunk in self.hunks:
            result.extend(hunk.removed_lines)
        return result

    @property
    def all_changed_lines(self) -> list[DiffLine]:
        """All changed (added + removed) lines."""
        return self.added_lines + self.removed_lines

    @property
    def extension(self) -> str:
        """File extension (e.g., '.rs', '.toml')."""
        return Path(self.path).suffix

    @property
    def filename(self) -> str:
        """Just the filename without directory."""
        return Path(self.path).name

    @property
    def is_rust_file(self) -> bool:
        return self.extension == ".rs"

    def get_full_new_content(self, repo_root: str) -> str | None:
        """Read the full file content from disk (post-change)."""
        if self.is_deleted:
            return None
        full_path = Path(repo_root) / self.path
        if full_path.exists():
            return full_path.read_text(encoding="utf-8", errors="replace")
        return None


# Regex patterns for parsing unified diff format
_DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
_OLD_FILE = re.compile(r"^--- (?:a/(.+)|/dev/null)$")
_NEW_FILE = re.compile(r"^\+\+\+ (?:b/(.+)|/dev/null)$")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
_RENAME_FROM = re.compile(r"^rename from (.+)$")
_RENAME_TO = re.compile(r"^rename to (.+)$")
_NEW_FILE_MODE = re.compile(r"^new file mode \d+$")
_DELETED_FILE_MODE = re.compile(r"^deleted file mode \d+$")
_BINARY_FILES = re.compile(r"^Binary files")
_SIMILARITY_INDEX = re.compile(r"^similarity index \d+%$")


def parse_diff(diff_text: str) -> list[ChangedFile]:
    """Parse unified diff text into a list of ChangedFile objects.

    Args:
        diff_text: Raw output from `git diff`.

    Returns:
        List of ChangedFile objects with parsed hunks and lines.
    """
    files: list[ChangedFile] = []
    current_file: ChangedFile | None = None
    current_hunk: DiffHunk | None = None
    new_line_num = 0

    for raw_line in diff_text.split("\n"):
        # New file diff header
        m = _DIFF_HEADER.match(raw_line)
        if m:
            # Save previous file
            if current_file is not None:
                files.append(current_file)
            current_file = ChangedFile(
                path=m.group(2),
                old_path=None,
                is_new=False,
                is_deleted=False,
                is_renamed=False,
                is_binary=False,
            )
            current_hunk = None
            continue

        if current_file is None:
            continue

        # Detect new/deleted/renamed/binary
        if _NEW_FILE_MODE.match(raw_line):
            current_file.is_new = True
            continue
        if _DELETED_FILE_MODE.match(raw_line):
            current_file.is_deleted = True
            continue
        if _BINARY_FILES.match(raw_line):
            current_file.is_binary = True
            continue
        if _SIMILARITY_INDEX.match(raw_line):
            current_file.is_renamed = True
            continue

        m = _RENAME_FROM.match(raw_line)
        if m:
            current_file.old_path = m.group(1)
            current_file.is_renamed = True
            continue

        m = _RENAME_TO.match(raw_line)
        if m:
            current_file.path = m.group(1)
            continue

        # Old/new file paths (--- / +++)
        m = _OLD_FILE.match(raw_line)
        if m:
            if m.group(1) is None:
                current_file.is_new = True
            continue

        m = _NEW_FILE.match(raw_line)
        if m:
            if m.group(1) is None:
                current_file.is_deleted = True
            elif m.group(1):
                current_file.path = m.group(1)
            continue

        # Hunk header
        m = _HUNK_HEADER.match(raw_line)
        if m:
            current_hunk = DiffHunk(
                old_start=int(m.group(1)),
                old_count=int(m.group(2) or "1"),
                new_start=int(m.group(3)),
                new_count=int(m.group(4) or "1"),
                header=raw_line,
            )
            current_file.hunks.append(current_hunk)
            new_line_num = current_hunk.new_start
            continue

        if current_hunk is None:
            continue

        # Diff content lines
        if raw_line.startswith("+"):
            current_hunk.lines.append(
                DiffLine(
                    line_number=new_line_num,
                    content=raw_line[1:],
                    is_added=True,
                    is_removed=False,
                    is_context=False,
                )
            )
            new_line_num += 1
        elif raw_line.startswith("-"):
            current_hunk.lines.append(
                DiffLine(
                    line_number=0,  # Removed lines don't have a new-file line number
                    content=raw_line[1:],
                    is_added=False,
                    is_removed=True,
                    is_context=False,
                )
            )
        elif raw_line.startswith(" "):
            current_hunk.lines.append(
                DiffLine(
                    line_number=new_line_num,
                    content=raw_line[1:],
                    is_added=False,
                    is_removed=False,
                    is_context=True,
                )
            )
            new_line_num += 1
        # Lines starting with \ (e.g., "\ No newline at end of file") are skipped

    # Don't forget the last file
    if current_file is not None:
        files.append(current_file)

    return files


def get_diff(
    base_branch: str = "main",
    repo_root: str | None = None,
) -> str:
    """Get the git diff between the current branch and a base branch.

    Args:
        base_branch: The branch to diff against (default: main).
        repo_root: Path to the repository root. If None, uses cwd.

    Returns:
        Raw diff text from git.
    """
    cmd = ["git", "diff", f"{base_branch}...HEAD", "--unified=3"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=60,
    )
    if result.returncode != 0:
        # Fallback: try without the three-dot notation
        cmd = ["git", "diff", base_branch, "--unified=3"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def get_staged_diff(repo_root: str | None = None) -> str:
    """Get the diff of staged changes."""
    cmd = ["git", "diff", "--cached", "--unified=3"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git diff --cached failed: {result.stderr.strip()}")
    return result.stdout


def get_changed_files_list(
    base_branch: str = "main",
    repo_root: str | None = None,
) -> list[str]:
    """Get just the list of changed file paths (without full diff)."""
    cmd = ["git", "diff", f"{base_branch}...HEAD", "--name-only"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=30,
    )
    if result.returncode != 0:
        cmd = ["git", "diff", base_branch, "--name-only"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git diff --name-only failed: {result.stderr.strip()}")
    return [f for f in result.stdout.strip().split("\n") if f]
