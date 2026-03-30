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
        return set(self._state.get("processed_threads", {}).keys())

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
    ) -> None:
        threads = self._state.setdefault("processed_threads", {})
        threads[thread_id] = {
            "pr_number": pr_number,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "status": "fixed",
            "commit_sha": commit_sha,
            "path": path,
            "instruction_preview": instruction[:200],
        }
        self.save()

    def mark_failed(self, thread_id: str, pr_number: int, error: str) -> None:
        threads = self._state.setdefault("processed_threads", {})
        threads[thread_id] = {
            "pr_number": pr_number,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "status": "failed",
            "error": error[:500],
        }
        self.save()

    def update_last_poll(self) -> None:
        self._state["last_poll"] = datetime.now(timezone.utc).isoformat()
        self.save()

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
