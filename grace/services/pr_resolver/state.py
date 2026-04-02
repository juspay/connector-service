"""State management for the PR Resolver service with file-based locking."""

import fcntl
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

_EMPTY_STATE: Dict[str, Any] = {
    "version": 1,
    "processed_threads": {},
    "last_poll": None,
}


class StateManager:
    """Manages PR resolver state with a JSON file backend and fcntl locking."""

    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self._state: Dict[str, Any] = dict(_EMPTY_STATE)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> Dict[str, Any]:
        """Load state from disk. Creates the file if it doesn't exist."""
        if not self.state_file.exists():
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state = dict(_EMPTY_STATE)
            self.save()
            return self._state

        try:
            with open(self.state_file, "r") as fh:
                fcntl.flock(fh, fcntl.LOCK_SH)
                try:
                    self._state = json.load(fh)
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load state file %s: %s — starting fresh", self.state_file, exc)
            self._state = dict(_EMPTY_STATE)
            self.save()

        return self._state

    def save(self) -> None:
        """Persist current state to disk with exclusive lock."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                json.dump(self._state, fh, indent=2, default=str)
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_processed(self, thread_id: str) -> bool:
        return thread_id in self._state.get("processed_threads", {})

    def get_processed_ids(self) -> Set[str]:
        """Return thread IDs that should be skipped. Excludes build_blocked
        (those need to be re-checked every cycle for new commits)."""
        threads = self._state.get("processed_threads", {})
        return {tid for tid, t in threads.items() if t.get("status") != "build_blocked"}

    def retry(self, thread_id: str) -> bool:
        """Remove a thread from processed state so it gets picked up again."""
        threads = self._state.get("processed_threads", {})
        if thread_id in threads:
            del threads[thread_id]
            self.save()
            return True
        return False

    def retry_all_failed(self) -> int:
        """Remove all failed threads from processed state. Returns count."""
        threads = self._state.get("processed_threads", {})
        to_remove = [tid for tid, e in threads.items() if e.get("status") == "failed"]
        for tid in to_remove:
            del threads[tid]
        if to_remove:
            self.save()
        return len(to_remove)

    # ------------------------------------------------------------------
    # Update helpers
    # ------------------------------------------------------------------

    def mark_fixed(
        self,
        thread_id: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        instruction: str,
        resolution_summary: str = "",
    ) -> None:
        threads = self._state.setdefault("processed_threads", {})
        threads[thread_id] = {
            "pr_number": pr_number,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "status": "fixed",
            "commit_sha": commit_sha,
            "path": path,
            "instruction_preview": instruction[:200],
            "resolution_summary": resolution_summary[:500],
        }
        self.save()

    def mark_failed(self, thread_id: str, pr_number: int, error: str) -> None:
        threads = self._state.setdefault("processed_threads", {})
        threads[thread_id] = {
            "pr_number": pr_number,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "status": "failed",
            "error": error[:3000],
        }
        self.save()

    def update_last_poll(self) -> None:
        self._state["last_poll"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def mark_build_failed(self, pr_number: int, branch: str, head_sha: str, error: str, thread_ids: list = None) -> None:
        """Mark a PR branch as having a broken build. Retries when SHA changes.

        Also marks affected threads as 'build_blocked' so they show in the dashboard
        but auto-clear when new commits are pushed.
        """
        builds = self._state.setdefault("build_failures", {})
        builds[str(pr_number)] = {
            "branch": branch,
            "head_sha": head_sha,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "error": error[:3000],
        }
        # Mark threads as blocked (not failed — they'll auto-retry on new commits)
        if thread_ids:
            threads = self._state.setdefault("processed_threads", {})
            for tid in thread_ids:
                threads[tid] = {
                    "pr_number": pr_number,
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                    "status": "build_blocked",
                    "error": f"Branch build broken — will auto-retry when new commits are pushed",
                }
        self.save()

    def should_skip_build(self, pr_number: int, current_sha: str) -> bool:
        """Check if we should skip this PR because its build already failed.

        Returns True if the SHA hasn't changed since the last failure (no new commits).
        Returns False if SHA changed (user pushed a fix) or no failure recorded.
        """
        builds = self._state.get("build_failures", {})
        entry = builds.get(str(pr_number))
        if not entry:
            return False
        # SHA changed → new commit → retry
        if entry.get("head_sha") != current_sha:
            # Clear the old failure and unblock threads
            del builds[str(pr_number)]
            # Remove build_blocked threads for this PR so they get picked up again
            threads = self._state.get("processed_threads", {})
            to_unblock = [tid for tid, t in threads.items()
                          if t.get("pr_number") == pr_number and t.get("status") == "build_blocked"]
            for tid in to_unblock:
                del threads[tid]
            self.save()
            return False
        return True

    def cleanup_old_entries(self, max_age_days: int = 30) -> int:
        """Remove entries older than *max_age_days*. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        threads: Dict[str, Any] = self._state.get("processed_threads", {})
        to_remove = []
        for tid, entry in threads.items():
            processed_at = entry.get("processed_at")
            if processed_at:
                try:
                    ts = datetime.fromisoformat(processed_at)
                    if ts < cutoff:
                        to_remove.append(tid)
                except (ValueError, TypeError):
                    pass
        for tid in to_remove:
            del threads[tid]
        if to_remove:
            self.save()
        return len(to_remove)
