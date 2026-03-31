"""Clone pool — manages up to N independent repo clones for concurrent PR processing.

Each clone is a full git checkout that can be independently checked out to any PR branch.
This allows processing multiple PRs simultaneously without interference.
"""

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CloneSlot:
    """A single repo clone slot."""

    slot_id: int
    path: Path
    busy: bool = False
    pr_number: Optional[int] = None
    push_remote: str = "origin"  # Set by checkout_pr for fork-based PRs


async def _run(cmd: List[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
    """Run a subprocess. Returns (returncode, stdout, stderr)."""
    logger.debug("clone_pool: %s (cwd=%s)", " ".join(cmd), cwd)
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
        return -1, "", f"Timed out after {timeout}s"
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


class ClonePool:
    """Manages a pool of independent repo clones for concurrent PR processing.

    Usage::

        pool = ClonePool(base_dir=Path("~/.grace/clones"), repo_url="https://github.com/juspay/hyperswitch-prism.git", max_slots=3)
        await pool.initialize()

        slot = await pool.acquire(pr_number=692)
        # ... do work in slot.path ...
        await pool.release(slot)
    """

    def __init__(self, base_dir: Path, repo_url: str, max_slots: int = 3) -> None:
        self.base_dir = base_dir
        self.repo_url = repo_url
        self.max_slots = max_slots
        self._slots: List[CloneSlot] = []
        self._semaphore = asyncio.Semaphore(max_slots)
        self._lock = asyncio.Lock()  # Protects slot assignment

    async def initialize(self) -> None:
        """Create clone directories if they don't exist. Safe to call multiple times."""
        self.base_dir.mkdir(parents=True, exist_ok=True)

        for i in range(self.max_slots):
            slot_dir = self.base_dir / f"slot-{i}"
            git_dir = slot_dir / ".git"

            if not git_dir.exists():
                logger.info("Cloning repo into slot-%d ...", i)
                rc, out, err = await _run(
                    ["git", "clone", self.repo_url, str(slot_dir)],
                    self.base_dir,
                    timeout=1200,
                )
                if rc != 0:
                    logger.error("Failed to clone into slot-%d: %s", i, err)
                    # Create directory anyway so we can try again later
                    slot_dir.mkdir(parents=True, exist_ok=True)
            else:
                # Ensure it's on main and clean
                await _run(["git", "checkout", "main"], slot_dir)
                await _run(["git", "clean", "-fd"], slot_dir)

            self._slots.append(CloneSlot(slot_id=i, path=slot_dir))

        logger.info("Clone pool ready: %d slots", len(self._slots))

    async def acquire(self, pr_number: int) -> Optional[CloneSlot]:
        """Acquire a free clone slot for a PR.

        Blocks until a slot is available (respects max_slots semaphore).
        Returns None only if the pool hasn't been initialized.
        """
        await self._semaphore.acquire()

        async with self._lock:
            for slot in self._slots:
                if not slot.busy:
                    slot.busy = True
                    slot.pr_number = pr_number
                    logger.info("Acquired slot-%d for PR #%d", slot.slot_id, pr_number)
                    return slot

        # Should not reach here if semaphore count matches slot count
        self._semaphore.release()
        return None

    async def release(self, slot: CloneSlot) -> None:
        """Release a slot back to the pool after processing."""
        logger.info("Releasing slot-%d (was PR #%s)", slot.slot_id, slot.pr_number)

        # Reset the clone to a clean state
        await _run(["git", "checkout", "main"], slot.path)
        await _run(["git", "clean", "-fd"], slot.path)
        await _run(["git", "checkout", "."], slot.path)

        async with self._lock:
            slot.busy = False
            slot.pr_number = None

        self._semaphore.release()

    async def checkout_pr(self, slot: CloneSlot, pr_number: int) -> tuple[bool, str]:
        """Checkout a PR branch and set up push remote for fork-based PRs."""
        await _run(["git", "fetch", "origin"], slot.path, timeout=60)

        # Checkout the PR branch
        rc, out, err = await _run(
            ["gh", "pr", "checkout", str(pr_number), "--force"],
            slot.path,
            timeout=120,
        )
        if rc != 0:
            return False, f"gh pr checkout failed: {err}"

        # Detect if PR is from a fork and add the fork as a push remote
        rc, owner_out, _ = await _run(
            ["gh", "pr", "view", str(pr_number), "--json", "headRepositoryOwner,headRepository",
             "--jq", ".headRepositoryOwner.login + \"/\" + .headRepository.name"],
            slot.path,
            timeout=15,
        )
        if rc == 0 and owner_out.strip():
            fork_slug = owner_out.strip()  # e.g., "10xGRACE/connector-service"
            fork_url = f"https://github.com/{fork_slug}.git"

            # Check if origin is different from fork (i.e., it's a fork-based PR)
            _, origin_url, _ = await _run(["git", "remote", "get-url", "origin"], slot.path)
            if fork_slug.lower() not in origin_url.strip().lower():
                # Add fork remote (or update if exists)
                fork_remote = "fork"
                await _run(["git", "remote", "remove", fork_remote], slot.path)
                await _run(["git", "remote", "add", fork_remote, fork_url], slot.path)
                await _run(["git", "fetch", fork_remote], slot.path, timeout=60)
                logger.info("Added fork remote: %s -> %s", fork_remote, fork_url)
                # Store which remote to push to
                slot.push_remote = fork_remote
            else:
                slot.push_remote = "origin"
        else:
            slot.push_remote = "origin"

        return True, ""

    # ------------------------------------------------------------------
    # Build / verification helpers (run inside a clone slot)
    # ------------------------------------------------------------------

    async def cargo_build(self, slot: CloneSlot) -> Tuple[bool, str]:
        """Run cargo check via shell to capture full stderr output."""
        # Use shell=True with 2>&1 to merge streams and capture everything
        proc = await asyncio.create_subprocess_shell(
            "CARGO_TERM_COLOR=never cargo check --package connector-integration 2>&1",
            cwd=str(slot.path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, "cargo check timed out after 600s"

        output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
        output = output.strip()
        return (proc.returncode or 0) == 0, output if (proc.returncode or 0) != 0 else "OK"

    async def cargo_clippy(self, slot: CloneSlot) -> Tuple[bool, str]:
        """Run cargo clippy. Allow warnings in deps, only deny in connector-integration."""
        rc, out, err = await _run(
            ["cargo", "clippy", "--package", "connector-integration", "--", "-W", "clippy::all"],
            slot.path,
            timeout=600,
        )
        output = (out + "\n" + err).strip()
        # Only fail if warnings/errors are in connector-integration, not in dependencies
        if rc != 0:
            lines = output.split("\n")
            connector_errors = [l for l in lines if "connector-integration" in l and ("error" in l.lower() or "warning" in l.lower())]
            if not connector_errors:
                # All errors are in dependencies — pass
                return True, ""
        return rc == 0, output

    async def cargo_build_and_clippy(self, slot: CloneSlot) -> Tuple[bool, str]:
        """Run cargo check + cargo clippy. Returns (both_passed, error_output).

        Uses `cargo check` (type checking only, no codegen) for speed.
        Only runs clippy if check passes.
        """
        check_ok, check_output = await self.cargo_build(slot)
        if not check_ok:
            return False, f"cargo check failed:\n{check_output}"

        clippy_ok, clippy_output = await self.cargo_clippy(slot)
        if not clippy_ok:
            return False, f"cargo clippy failed:\n{clippy_output}"

        return True, ""

    async def git_stage_connector(self, slot: CloneSlot, connector: str) -> Tuple[bool, str]:
        """Stage only files belonging to a specific connector."""
        # Stage both the connector .rs file and its directory
        patterns = [
            f"crates/integrations/connector-integration/src/connectors/{connector}.rs",
            f"crates/integrations/connector-integration/src/connectors/{connector}/",
        ]
        rc, out, err = await _run(
            ["git", "add"] + patterns,
            slot.path,
        )
        return rc == 0, err

    async def git_commit_connector(self, slot: CloneSlot, connector: str, message: str) -> Tuple[bool, str]:
        """Commit staged changes. Returns (success, sha_or_error)."""
        rc, out, err = await _run(
            ["git", "commit", "-m", message],
            slot.path,
        )
        if rc != 0:
            return False, err.strip()
        # Get commit SHA
        rc, sha, _ = await _run(["git", "rev-parse", "HEAD"], slot.path)
        return True, sha.strip()

    async def git_push(self, slot: CloneSlot, branch: str, pr_number: int = 0) -> Tuple[bool, str]:
        """Push to the correct remote — uses slot.push_remote set by checkout_pr."""
        remote = slot.push_remote or "origin"
        logger.info("Pushing to remote '%s' for branch '%s'", remote, branch)

        rc, out, err = await _run(
            ["git", "push", remote, f"HEAD:{branch}"],
            slot.path,
            timeout=60,
        )
        if rc == 0:
            return True, out.strip()

        return False, f"Push to {remote} failed: {err}"

    async def git_revert_all(self, slot: CloneSlot) -> None:
        """Discard all uncommitted changes in the clone."""
        await _run(["git", "checkout", "."], slot.path)
        await _run(["git", "clean", "-fd"], slot.path)

    async def git_changed_files(self, slot: CloneSlot) -> List[str]:
        """Get list of modified/added files."""
        _, out, _ = await _run(["git", "status", "--porcelain"], slot.path)
        return [line[3:].strip() for line in out.strip().splitlines() if len(line) > 3]

    @property
    def status(self) -> List[dict]:
        """Return current pool status for dashboard display."""
        return [
            {
                "slot_id": s.slot_id,
                "busy": s.busy,
                "pr_number": s.pr_number,
                "path": str(s.path),
            }
            for s in self._slots
        ]

    @property
    def free_count(self) -> int:
        return sum(1 for s in self._slots if not s.busy)

    @property
    def busy_count(self) -> int:
        return sum(1 for s in self._slots if s.busy)
