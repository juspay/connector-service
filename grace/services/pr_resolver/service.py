"""Main PR Resolver service — poll loop with freshness gates.

ARCHITECTURE: PR branch checkouts happen in git worktrees so the main repo
directory (where the service code lives) is never disturbed.
"""

import asyncio
import fcntl
import logging
import os
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import PRResolverConfig
from .display import (
    display_comment_list,
    display_commit,
    display_cycle_start,
    display_cycle_summary,
    display_error,
    display_gate,
    display_no_comments,
    display_pr_processing,
    display_reply_posted,
    display_resolve_done,
    display_resolving,
    display_skip,
)
from .git import GitOperations
from .github import GitHubClient, TriggeredThread, filter_triggered_threads
from .resolver import CommentResolver, ResolveResult
from .state import StateManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File lock
# ---------------------------------------------------------------------------


class FileLock:
    """Simple fcntl-based file lock."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "w")
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self._fh.close()
            self._fh = None
            return False

    def release(self) -> None:
        if self._fh:
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
            except OSError:
                pass
            self._fh = None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class PRResolverService:
    """Polls GitHub for @10xGrace-triggered review comments and resolves them."""

    def __init__(
        self,
        config: PRResolverConfig,
        event_callback: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.event_callback = event_callback

        self.state = StateManager(config.state_file)
        self.git = GitOperations(config.repo_path)
        self.github = GitHubClient(config.owner, config.repo)

        # Claude SDK config — from env with Grace config fallback
        self.claude_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.claude_base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        self.claude_model = os.environ.get("CLAUDE_MODEL", "")

        self._cycle = 0

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    async def _emit(self, event_type: str, **data: Any) -> None:
        if self.event_callback is None:
            return
        try:
            result = self.event_callback(event_type, **data)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            logger.error("Event callback error for %s:\n%s", event_type, traceback.format_exc())

    async def _gate(self, name: str, passed: bool, detail: str = "") -> bool:
        display_gate(name, passed, detail)
        await self._emit("gate", name=name, passed=passed, detail=detail)
        return passed

    # ------------------------------------------------------------------
    # Main loops
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        """Poll loop — runs until interrupted."""
        logger.info("PR Resolver starting (interval=%ds)", self.config.poll_interval)
        while True:
            try:
                await self.run_once()
            except KeyboardInterrupt:
                logger.info("Shutting down")
                break
            except Exception:
                logger.exception("Unexpected error in poll cycle")
                display_error(traceback.format_exc())
            await asyncio.sleep(self.config.poll_interval)

    async def run_once(self) -> Dict[str, Any]:
        """Run a single poll cycle. Returns a summary dict."""
        self._cycle += 1
        display_cycle_start(self._cycle)
        await self._emit("cycle_start", cycle=self._cycle)

        lock = FileLock(self.config.lock_file)
        if not lock.acquire():
            display_error("Another instance is running (lock held)")
            return {"error": "lock_held"}

        summary: Dict[str, Any] = {"cycle": self._cycle, "fixed": 0, "failed": 0, "skipped": 0, "total": 0}

        try:
            self.state.load()
            self.state.cleanup_old_entries()

            # Fetch open PRs
            prs = await self.github.fetch_open_prs_with_threads()
            processed_ids = self.state.get_processed_ids()

            # Filter for triggered threads
            all_triggered: List[TriggeredThread] = []
            for pr in prs:
                triggered = filter_triggered_threads(pr, self.config.trigger_tag, processed_ids)
                all_triggered.extend(triggered)

            self.state.update_last_poll()

            if not all_triggered:
                display_no_comments()
                await self._emit("no_comments")
                return summary

            # Cap per cycle
            if len(all_triggered) > self.config.max_comments_per_cycle:
                all_triggered = all_triggered[: self.config.max_comments_per_cycle]

            summary["total"] = len(all_triggered)

            # Display comment list
            display_comment_list(
                [
                    {
                        "path": t.path,
                        "line": t.line,
                        "author": t.author,
                        "instruction": t.instruction,
                    }
                    for t in all_triggered
                ]
            )

            # Emit comment_found events
            for t in all_triggered:
                await self._emit("comment_found", pr=t.pr_number, path=t.path, line=t.line, author=t.author, instruction=t.instruction[:100])

            # Group by PR
            by_pr: Dict[int, List[TriggeredThread]] = {}
            for t in all_triggered:
                by_pr.setdefault(t.pr_number, []).append(t)

            for pr_number, threads in by_pr.items():
                branch = threads[0].pr_branch
                await self._emit("pr_start", pr_number=pr_number, title=f"PR #{pr_number}", thread_count=len(threads))
                result = await self._process_pr(branch, threads, pr_number)
                summary["fixed"] += result.get("fixed", 0)
                summary["failed"] += result.get("failed", 0)
                summary["skipped"] += result.get("skipped", 0)

        except Exception:
            logger.exception("Error in poll cycle %d", self._cycle)
            display_error(traceback.format_exc())
        finally:
            lock.release()

        display_cycle_summary(
            self._cycle,
            summary["total"],
            summary["fixed"],
            summary["failed"],
            summary["skipped"],
        )
        await self._emit("cycle_end", fixed=summary["fixed"], failed=summary["failed"], skipped=summary["skipped"])
        return summary

    # ------------------------------------------------------------------
    # Per-PR processing with 6 freshness gates
    # ------------------------------------------------------------------

    async def _process_pr(
        self,
        branch: str,
        threads: List[TriggeredThread],
        pr_number: int,
    ) -> Dict[str, int]:
        counts = {"fixed": 0, "failed": 0, "skipped": 0}
        display_pr_processing(pr_number, branch, len(threads))

        # --- Gate 1: PR still OPEN ---
        pr_info = await self.github.fetch_pr_threads(pr_number)
        if not await self._gate("PR still open", pr_info is not None and pr_info.state == "OPEN",
                          f"state={pr_info.state if pr_info else 'NOT_FOUND'}"):
            counts["skipped"] = len(threads)
            return counts

        # --- Gate 2: Fetch and reset (WORKTREE) ---
        ok, err, work_dir = await self.git.fetch_and_reset(branch, pr_number=pr_number)
        if not await self._gate("Checkout branch", ok, err):
            counts["skipped"] = len(threads)
            return counts

        try:
            return await self._process_pr_in_worktree(branch, threads, pr_number, pr_info, work_dir)
        finally:
            # Always clean up the worktree
            if work_dir != self.config.repo_path:
                await self.git.cleanup_worktree(pr_number=pr_number)

    async def _process_pr_in_worktree(
        self,
        branch: str,
        threads: List[TriggeredThread],
        pr_number: int,
        pr_info: Any,
        work_dir: Path,
    ) -> Dict[str, int]:
        counts = {"fixed": 0, "failed": 0, "skipped": 0}

        # --- Gate 3: Re-verify threads still unresolved ---
        still_open = []
        for t in threads:
            thread_still_open = False
            for rt in (pr_info.threads if pr_info else []):
                if rt.id == t.thread_id and not rt.is_resolved:
                    thread_still_open = True
                    break
            if thread_still_open:
                still_open.append(t)
            else:
                display_skip(t.thread_id, "already resolved")
                counts["skipped"] += 1

        if not await self._gate("Threads still unresolved", len(still_open) > 0,
                          f"{len(still_open)}/{len(threads)} still open"):
            return counts

        threads = still_open

        # --- Gate 4: Baseline cargo check ---
        from .git import _run
        rc, out, err = await _run(["cargo", "check"], work_dir, timeout=300)
        baseline_ok = rc == 0
        if not await self._gate("Baseline cargo check", baseline_ok,
                          err[:200] if not baseline_ok else "OK"):
            counts["skipped"] = len(threads)
            return counts

        # --- Resolve with Claude ---
        display_resolving(len(threads))
        resolver = CommentResolver(
            repo_path=work_dir,
            index_dir=self.config.index_dir,
            claude_api_key=self.claude_api_key,
            claude_base_url=self.claude_base_url,
            claude_model=self.claude_model,
            event_callback=self.event_callback,
        )
        result: ResolveResult = await resolver.resolve_comments(threads)
        display_resolve_done(len(result.fixed_threads), len(result.failed_threads), result.turn_count)

        if result.error:
            display_error(result.error)
            for t in threads:
                self.state.mark_failed(t.thread_id, pr_number, result.error)
            counts["failed"] = len(threads)
            return counts

        # --- Post-fix build check ---
        if result.modified_files:
            rc, out, err = await _run(["cargo", "check"], work_dir, timeout=300)
            if rc != 0:
                display_error(f"Post-fix cargo check failed: {err[:200]}")
                await self.git.revert_all(cwd=work_dir)
                for t in threads:
                    self.state.mark_failed(t.thread_id, pr_number, f"cargo check failed: {err[:200]}")
                counts["failed"] = len(threads)
                return counts

        # --- Gate 5: Pre-push remote HEAD check ---
        ok, remote_sha = await self.git.get_remote_head(branch, cwd=work_dir)
        local_sha_before = await self.git.get_current_head(cwd=work_dir)
        # We just need to verify the branch hasn't diverged unexpectedly
        if not await self._gate("Remote HEAD check", ok, remote_sha[:12] if ok else remote_sha):
            await self.git.revert_all(cwd=work_dir)
            counts["skipped"] = len(threads)
            return counts

        # --- Gate 6: Pre-push thread re-verify ---
        pr_info_fresh = await self.github.fetch_pr_threads(pr_number)
        threads_still_open = 0
        if pr_info_fresh:
            for t in threads:
                for rt in pr_info_fresh.threads:
                    if rt.id == t.thread_id and not rt.is_resolved:
                        threads_still_open += 1
                        break
        if not await self._gate("Pre-push thread re-verify", threads_still_open > 0,
                          f"{threads_still_open}/{len(threads)} still open"):
            await self.git.revert_all(cwd=work_dir)
            counts["skipped"] = len(threads)
            return counts

        # --- Stage, commit, push ---
        if not await self.git.has_changes(cwd=work_dir):
            display_skip("all", "no changes produced")
            counts["skipped"] = len(threads)
            return counts

        changed = await self.git.get_changed_files(cwd=work_dir)
        ok, stage_err = await self.git.stage_files(changed, cwd=work_dir)
        if not ok:
            display_error(f"git add failed: {stage_err}")
            counts["failed"] = len(threads)
            return counts

        instructions_preview = "; ".join(t.instruction[:60] for t in threads[:3])
        commit_msg = f"fix(review): resolve {len(threads)} comment(s) on PR #{pr_number}\n\n{instructions_preview}"
        ok, sha = await self.git.commit(commit_msg, cwd=work_dir)
        if not ok:
            display_error(f"git commit failed: {sha}")
            counts["failed"] = len(threads)
            return counts

        display_commit(sha, commit_msg.split("\n")[0])

        ok, push_err = await self.git.push(branch, cwd=work_dir)
        if not ok:
            # Try pull --rebase and retry
            ok2, _ = await self.git.pull_rebase(branch, cwd=work_dir)
            if ok2:
                ok, push_err = await self.git.push(branch, cwd=work_dir)
            if not ok:
                display_error(f"git push failed: {push_err}")
                counts["failed"] = len(threads)
                return counts

        # --- Reply on threads ---
        for t in threads:
            body = (
                f"Resolved by commit `{sha[:8]}`. "
                f"Applied fix: {t.instruction[:200]}\n\n"
                f"-- 10xGrace PR Resolver"
            )
            posted = await self.github.post_thread_reply(t.thread_id, body)
            if posted:
                display_reply_posted(t.thread_id)
            self.state.mark_fixed(t.thread_id, pr_number, sha, t.path, t.instruction)
            counts["fixed"] += 1

        return counts
