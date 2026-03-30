"""Async git operations for the PR Resolver service.

KEY ARCHITECTURE: fetch_and_reset uses git worktrees for PR branch checkouts
so the main checkout (where the service itself lives) is never disturbed.
"""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


async def _run(
    cmd: List[str],
    cwd: Path,
    timeout: int = 120,
) -> Tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    logger.debug("Running: %s  (cwd=%s)", " ".join(cmd), cwd)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


class GitOperations:
    """Git helpers that operate on the repo at *repo_path*."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path

    # ------------------------------------------------------------------
    # Worktree-aware checkout
    # ------------------------------------------------------------------

    async def fetch_and_reset(
        self,
        branch: str,
        pr_number: int = 0,
    ) -> Tuple[bool, str, Path]:
        """Checkout a branch, returning ``(success, error, work_dir)``.

        When *pr_number* is set the checkout happens inside a **git worktree**
        so that the main repo directory (where the service lives) is never
        modified.  For plain branches the operation falls back to a normal
        fetch/checkout/reset in the main repo.
        """
        if pr_number:
            worktree_dir = self.repo_path / ".worktrees" / f"pr-{pr_number}"
            if not worktree_dir.exists():
                worktree_dir.parent.mkdir(parents=True, exist_ok=True)
                rc, out, err = await _run(
                    [
                        "git", "worktree", "add",
                        str(worktree_dir),
                        "--detach",
                    ],
                    self.repo_path,
                )
                if rc != 0:
                    return False, f"worktree add failed: {err}", self.repo_path

            # Checkout PR in worktree via gh CLI
            rc, out, err = await _run(
                ["gh", "pr", "checkout", str(pr_number), "--force"],
                worktree_dir,
                timeout=60,
            )
            if rc != 0:
                return False, f"gh pr checkout failed: {err}", self.repo_path

            return True, "", worktree_dir

        # Non-PR branch: standard fetch/checkout/reset in main repo
        rc, _, err = await _run(["git", "fetch", "origin"], self.repo_path)
        if rc != 0:
            return False, f"git fetch failed: {err}", self.repo_path

        rc, _, err = await _run(["git", "checkout", branch], self.repo_path)
        if rc != 0:
            return False, f"git checkout failed: {err}", self.repo_path

        rc, _, err = await _run(["git", "reset", "--hard", f"origin/{branch}"], self.repo_path)
        if rc != 0:
            return False, f"git reset failed: {err}", self.repo_path

        return True, "", self.repo_path

    # ------------------------------------------------------------------
    # Ref helpers
    # ------------------------------------------------------------------

    async def get_remote_head(self, branch: str, cwd: Optional[Path] = None) -> Tuple[bool, str]:
        """Return ``(ok, sha_or_error)`` for ``origin/<branch>``."""
        work = cwd or self.repo_path
        rc, _, _ = await _run(["git", "fetch", "origin"], work)
        rc, out, err = await _run(["git", "rev-parse", f"origin/{branch}"], work)
        if rc != 0:
            return False, err.strip()
        return True, out.strip()

    async def get_current_head(self, cwd: Optional[Path] = None) -> str:
        work = cwd or self.repo_path
        _, out, _ = await _run(["git", "rev-parse", "HEAD"], work)
        return out.strip()

    # ------------------------------------------------------------------
    # Staging / committing
    # ------------------------------------------------------------------

    async def stage_files(self, files: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str]:
        work = cwd or self.repo_path
        rc, _, err = await _run(["git", "add", "--"] + files, work)
        return rc == 0, err.strip()

    async def commit(self, message: str, cwd: Optional[Path] = None) -> Tuple[bool, str]:
        """Create a commit and return ``(ok, sha_or_error)``."""
        work = cwd or self.repo_path
        rc, _, err = await _run(["git", "commit", "-m", message], work)
        if rc != 0:
            return False, err.strip()
        sha = await self.get_current_head(work)
        return True, sha

    async def push(self, branch: str, cwd: Optional[Path] = None) -> Tuple[bool, str]:
        """Push to origin — never force-pushes."""
        work = cwd or self.repo_path
        rc, out, err = await _run(["git", "push", "origin", f"HEAD:{branch}"], work)
        if rc != 0:
            return False, err.strip()
        return True, out.strip()

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    async def pull_rebase(self, branch: str, cwd: Optional[Path] = None) -> Tuple[bool, str]:
        work = cwd or self.repo_path
        rc, out, err = await _run(["git", "pull", "--rebase", "origin", branch], work)
        if rc != 0:
            return False, err.strip()
        return True, out.strip()

    async def revert_all(self, cwd: Optional[Path] = None) -> None:
        work = cwd or self.repo_path
        await _run(["git", "checkout", "."], work)
        await _run(["git", "clean", "-fd"], work)

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    async def has_changes(self, cwd: Optional[Path] = None) -> bool:
        work = cwd or self.repo_path
        rc, out, _ = await _run(["git", "status", "--porcelain"], work)
        return bool(out.strip())

    async def get_changed_files(self, cwd: Optional[Path] = None) -> List[str]:
        work = cwd or self.repo_path
        _, out, _ = await _run(["git", "status", "--porcelain"], work)
        files: List[str] = []
        for line in out.strip().splitlines():
            if len(line) > 3:
                files.append(line[3:].strip())
        return files

    # ------------------------------------------------------------------
    # Worktree cleanup
    # ------------------------------------------------------------------

    async def cleanup_worktree(self, branch: str = "", pr_number: int = 0) -> None:
        """Remove a worktree created by fetch_and_reset."""
        if pr_number:
            worktree_dir = self.repo_path / ".worktrees" / f"pr-{pr_number}"
        elif branch:
            worktree_dir = self.repo_path / ".worktrees" / branch
        else:
            return

        if worktree_dir.exists():
            rc, _, err = await _run(
                ["git", "worktree", "remove", str(worktree_dir), "--force"],
                self.repo_path,
            )
            if rc != 0:
                logger.warning("git worktree remove failed: %s — trying shutil", err)
                try:
                    shutil.rmtree(worktree_dir, ignore_errors=True)
                except OSError:
                    pass

        # Prune stale worktree bookkeeping
        await _run(["git", "worktree", "prune"], self.repo_path)
