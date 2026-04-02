"""Main PR Resolver service — concurrent PRs, connector sub-tasks, build-fix loops.

ARCHITECTURE:
- Clone pool: 3 independent repo clones for concurrent PR processing
- Sub-tasks: comments grouped by connector, one Claude session + one commit per connector
- Build-fix loop: cargo build + clippy after each fix, loop back to Claude on failure (max 3)
- 6 freshness gates before pushing
"""

import asyncio
import fcntl
import logging
import os
import re
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .clone_pool import ClonePool, CloneSlot
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
from .github import GitHubClient, TriggeredThread, filter_triggered_threads
from .resolver import CommentResolver
from .state import StateManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_connector(path: str) -> str:
    """Extract connector name from a file path.

    'crates/integrations/connector-integration/src/connectors/adyen/transformers.rs' -> 'adyen'
    'crates/integrations/connector-integration/src/connectors/adyen.rs' -> 'adyen'
    """
    if "connectors/" in path:
        after = path.split("connectors/")[-1]
        return after.split("/")[0].replace(".rs", "")
    return "other"


def _is_question(instruction: str) -> bool:
    """Detect if a comment is a question rather than an actionable code change request."""
    text = instruction.strip().lower()
    # Ends with question mark
    if text.endswith("?"):
        return True
    # Starts with question words without actionable verbs
    question_starts = ("why ", "what ", "how ", "is this", "should ", "could ", "would ", "can ", "have you", "did you", "are you")
    if any(text.startswith(q) for q in question_starts):
        # But check for actionable intent: "can you fix this" is actionable
        actionable_overrides = ("can you ", "could you ", "please ", "fix", "change", "remove", "rename", "update", "add", "use ")
        if any(a in text for a in actionable_overrides):
            return False
        return True
    return False


def _group_by_connector(threads: List[TriggeredThread]) -> Dict[str, List[TriggeredThread]]:
    """Group triggered threads by connector name."""
    groups: Dict[str, List[TriggeredThread]] = defaultdict(list)
    for t in threads:
        connector = _extract_connector(t.path)
        groups[connector].append(t)
    return dict(groups)


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
    """Polls GitHub for @10xGrace comments and resolves them concurrently."""

    def __init__(
        self,
        config: PRResolverConfig,
        event_callback: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.event_callback = event_callback

        self.state = StateManager(config.state_file)
        self.github = GitHubClient(config.owner, config.repo)
        self.pool = ClonePool(
            base_dir=config.clone_dir,
            repo_url=config.repo_clone_url,
            max_slots=config.max_concurrent_prs,
        )

        # Claude SDK config
        self.claude_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.claude_base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        self.claude_model = os.environ.get("CLAUDE_MODEL", "")

        self._cycle = 0
        self._pool_initialized = False
        self._resolve_summaries: Dict[str, str] = {}  # thread_id -> Claude's summary of what changed

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
            logger.error("Event emit error (%s): %s", event_type, traceback.format_exc())

    async def _gate(self, name: str, passed: bool, detail: str = "", pr: int = 0, connector: str = "", output: str = "") -> bool:
        display_gate(name, passed, detail[:200])
        if connector:
            await self._emit("subtask_gate", pr=pr, connector=connector, gate=name, passed=passed, detail=detail, output=output)
        else:
            await self._emit("gate", name=name, passed=passed, detail=detail, output=output, pr=pr)
        return passed

    def _is_authorized(self, thread: TriggeredThread) -> bool:
        """Check if the comment author is authorized to trigger the bot."""
        if thread.author in self.config.blocked_users:
            return False
        if self.config.allowed_users and thread.author in self.config.allowed_users:
            return True
        return thread.author_association in self.config.allowed_associations

    # ------------------------------------------------------------------
    # Main loops
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        logger.info("10xGrace starting (interval=%ds, max_concurrent=%d)", self.config.poll_interval, self.config.max_concurrent_prs)
        while True:
            try:
                await self.run_once()
            except KeyboardInterrupt:
                break
            except Exception:
                logger.exception("Cycle error")
                display_error(traceback.format_exc())
            await asyncio.sleep(self.config.poll_interval)

    async def run_once(self) -> Dict[str, Any]:
        """Single poll cycle: poll → filter → concurrent PR processing."""
        self._cycle += 1
        display_cycle_start(self._cycle)
        await self._emit("cycle_start", cycle=self._cycle)

        # Initialize clone pool on first run
        if not self._pool_initialized:
            logger.info("Initializing clone pool...")
            await self.pool.initialize()
            self._pool_initialized = True

        lock = FileLock(self.config.lock_file)
        if not lock.acquire():
            display_error("Lock held by another instance")
            return {"error": "lock_held"}

        summary: Dict[str, Any] = {"cycle": self._cycle, "fixed": 0, "failed": 0, "skipped": 0, "total": 0, "queued": 0}

        try:
            self.state.load()
            self.state.cleanup_old_entries()

            # Poll GitHub
            prs = await self.github.fetch_open_prs_with_threads()
            processed_ids = self.state.get_processed_ids()

            # Filter for @10xGrace
            all_triggered: List[TriggeredThread] = []
            for pr in prs:
                triggered = filter_triggered_threads(pr, self.config.trigger_tag, processed_ids)
                all_triggered.extend(triggered)

            self.state.update_last_poll()

            if not all_triggered:
                display_no_comments()
                await self._emit("no_comments")
                return summary

            # Authorization check
            authorized = []
            for t in all_triggered:
                if self._is_authorized(t):
                    authorized.append(t)
                else:
                    if not self.state.is_processed(t.thread_id):
                        await self.github.post_thread_reply(
                            t.thread_id,
                            f"@{t.author} You don't have permission to trigger this bot. "
                            f"Only repository members and collaborators can use {self.config.trigger_tag}.\n\n— *10xGrace*"
                        )
                        self.state.mark_failed(t.thread_id, t.pr_number, f"Unauthorized: {t.author} ({t.author_association})")
                    await self._emit("comment_unauthorized", pr=t.pr_number, author=t.author,
                                     association=t.author_association, thread_id=t.thread_id)
            all_triggered = authorized

            if not all_triggered:
                display_no_comments()
                await self._emit("no_comments")
                return summary

            # Cap per cycle
            all_triggered = all_triggered[: self.config.max_comments_per_cycle]
            summary["total"] = len(all_triggered)

            display_comment_list([
                {"path": t.path, "line": t.line, "author": t.author, "instruction": t.instruction}
                for t in all_triggered
            ])

            for t in all_triggered:
                await self._emit("comment_found", pr=t.pr_number, path=t.path, line=t.line, author=t.author, instruction=t.instruction[:100], thread_id=t.thread_id)

            # Group by PR
            by_pr: Dict[int, List[TriggeredThread]] = defaultdict(list)
            for t in all_triggered:
                by_pr[t.pr_number].append(t)

            pr_list = list(by_pr.items())

            # Take up to max_concurrent_prs, queue the rest
            active_prs = pr_list[: self.config.max_concurrent_prs]
            queued_prs = pr_list[self.config.max_concurrent_prs:]

            for i, (pr_num, _) in enumerate(queued_prs):
                await self._emit("pr_queued", pr=pr_num, position=i + 1)
                summary["queued"] += 1

            # Process active PRs concurrently
            tasks = []
            for pr_number, threads in active_prs:
                await self._emit("pr_start", pr_number=pr_number, title=f"PR #{pr_number}", thread_count=len(threads))
                task = asyncio.create_task(self._process_pr(pr_number, threads))
                tasks.append((pr_number, task))

            # Wait for all concurrent PR tasks
            for pr_number, task in tasks:
                try:
                    result = await task
                    summary["fixed"] += result.get("fixed", 0)
                    summary["failed"] += result.get("failed", 0)
                    summary["skipped"] += result.get("skipped", 0)
                except Exception:
                    logger.exception("PR #%d processing failed", pr_number)
                    summary["failed"] += len(by_pr[pr_number])

        except Exception:
            logger.exception("Cycle %d error", self._cycle)
            display_error(traceback.format_exc())
        finally:
            lock.release()

        display_cycle_summary(self._cycle, summary["total"], summary["fixed"], summary["failed"], summary["skipped"])
        await self._emit("cycle_end", **summary)
        return summary

    # ------------------------------------------------------------------
    # Per-PR processing
    # ------------------------------------------------------------------

    async def _process_pr(self, pr_number: int, threads: List[TriggeredThread]) -> Dict[str, int]:
        """Process all @10xGrace comments for one PR using a clone slot."""
        counts = {"fixed": 0, "failed": 0, "skipped": 0}
        branch = threads[0].pr_branch

        display_pr_processing(pr_number, branch, len(threads))

        # GATE 1: PR still open
        pr_info = await self.github.fetch_pr_threads(pr_number)
        if not await self._gate("PR still open", pr_info is not None and pr_info.state == "OPEN",
                                f"state={pr_info.state if pr_info else 'NOT_FOUND'}", pr=pr_number):
            counts["skipped"] = len(threads)
            return counts

        # FAST CHECK: Is this PR's build already known to be broken? (no checkout needed)
        from .clone_pool import _run as _pool_run
        rc, sha_out, _ = await _pool_run(
            ["gh", "pr", "view", str(pr_number), "--repo", f"{self.config.owner}/{self.config.repo}",
             "--json", "headRefOid", "--jq", ".headRefOid"],
            self.config.repo_path, timeout=15,
        )
        current_sha = sha_out.strip() if rc == 0 else ""

        if current_sha and self.state.should_skip_build(pr_number, current_sha):
            stored = self.state._state.get("build_failures", {}).get(str(pr_number), {})
            stored_error = stored.get("error", "No error details available")
            await self._gate("Baseline build", False,
                             "Build failed previously — waiting for new commits",
                             pr=pr_number, output=stored_error)
            counts["skipped"] = len(threads)
            return counts

        # GATE 2: Acquire clone slot + checkout
        slot = await self.pool.acquire(pr_number)
        if slot is None:
            await self._gate("Clone slot", False, "no slots available", pr=pr_number)
            counts["skipped"] = len(threads)
            return counts
        await self._emit("clone_acquired", pr=pr_number, slot_id=slot.slot_id)

        try:
            ok, err = await self.pool.checkout_pr(slot, pr_number)
            if not await self._gate("Checkout branch", ok, err, pr=pr_number):
                counts["skipped"] = len(threads)
                return counts

            # GATE 3: Re-verify threads still unresolved
            still_open = threads
            if pr_info:
                resolved_ids = {rt.id for rt in pr_info.threads if rt.is_resolved}
                still_open = [t for t in threads if t.thread_id not in resolved_ids]

            if not await self._gate("Threads unresolved", len(still_open) > 0,
                                    f"{len(still_open)}/{len(threads)} open", pr=pr_number):
                counts["skipped"] = len(threads)
                return counts
            threads = still_open

            # GATE 4: Baseline cargo build
            build_ok, build_out = await self.pool.cargo_build(slot)
            if not await self._gate("Baseline build", build_ok, "Branch has build errors" if not build_ok else "OK", pr=pr_number, output=build_out if not build_ok else ""):
                # Mark with SHA so we don't retry until a new commit is pushed
                self.state.mark_build_failed(pr_number, branch, head_sha, build_out, thread_ids=[t.thread_id for t in threads])
                counts["skipped"] = len(threads)
                return counts

            # Add 👀 reaction to each comment to signal pickup
            for t in threads:
                if t.comment_node_id:
                    await self.github.add_reaction(t.comment_node_id, "EYES")

            # Triage: classify comments as actionable vs questions
            actionable_threads = []
            for t in threads:
                if _is_question(t.instruction):
                    if not self.state.is_processed(t.thread_id):
                        # Use Claude to answer the question with codebase context
                        connector = _extract_connector(t.path)
                        resolver = CommentResolver(
                            repo_path=slot.path,
                            index_dir=self.config.index_dir,
                            claude_api_key=self.claude_api_key,
                            claude_base_url=self.claude_base_url,
                            claude_model=self.claude_model,
                            max_turns=10,
                            event_callback=self.event_callback,
                        )
                        answer = await resolver.answer_question(t, connector, pr_number=pr_number)
                        reply = f"{answer}\n\n— *10xGrace*"
                        await self.github.post_thread_reply(t.thread_id, reply)
                    self.state.mark_failed(t.thread_id, pr_number, "Question — answered")
                    await self._emit("subtask_gate", pr=pr_number, connector=_extract_connector(t.path),
                                     gate="Triage", passed=True, detail="Question — answered with codebase context")
                    counts["skipped"] += 1
                else:
                    actionable_threads.append(t)

            threads = actionable_threads
            if not threads:
                await self._gate("Actionable comments", False, "all were questions", pr=pr_number)
                return counts

            # Group comments by connector
            by_connector = _group_by_connector(threads)
            logger.info("PR #%d: %d connector(s) to process: %s", pr_number, len(by_connector), list(by_connector.keys()))

            # Process each connector sub-task sequentially
            for connector, connector_threads in by_connector.items():
                result = await self._process_connector(slot, connector, connector_threads, pr_number, branch)
                counts["fixed"] += result.get("fixed", 0)
                counts["failed"] += result.get("failed", 0)
                counts["skipped"] += result.get("skipped", 0)

            # GATE 5+6 + Push (only if we have commits)
            if counts["fixed"] > 0:
                await self._push_and_reply(slot, branch, pr_number, threads, counts)

        finally:
            await self.pool.release(slot)
            await self._emit("clone_released", pr=pr_number, slot_id=slot.slot_id)

        return counts

    # ------------------------------------------------------------------
    # Per-connector sub-task with build-fix loop
    # ------------------------------------------------------------------

    async def _process_connector(
        self,
        slot: CloneSlot,
        connector: str,
        threads: List[TriggeredThread],
        pr_number: int,
        branch: str,
    ) -> Dict[str, int]:
        """Process all comments for one connector. Includes build-fix loop."""
        counts = {"fixed": 0, "failed": 0, "skipped": 0}

        display_resolving(len(threads))
        await self._emit("subtask_start", pr=pr_number, connector=connector, comment_count=len(threads))

        resolver = CommentResolver(
            repo_path=slot.path,
            index_dir=self.config.index_dir,
            claude_api_key=self.claude_api_key,
            claude_base_url=self.claude_base_url,
            claude_model=self.claude_model,
            max_turns=20,
            event_callback=self.event_callback,
        )

        # Initial Claude session
        resolve_result = await resolver.resolve_connector(connector, threads, pr_number=pr_number)

        if resolve_result.error:
            display_error(resolve_result.error)
            await self._emit("subtask_failed", pr=pr_number, connector=connector, error=resolve_result.error)
            for t in threads:
                self.state.mark_failed(t.thread_id, pr_number, resolve_result.error)
            counts["failed"] = len(threads)
            return counts

        # Check if Claude actually changed anything
        changed = await self.pool.git_changed_files(slot)
        if not changed:
            display_skip("all", f"no changes produced for {connector}")
            for t in threads:
                self.state.mark_failed(t.thread_id, pr_number, "No code changes produced — may already be fixed")
            counts["skipped"] = len(threads)
            return counts

        # === PHASE 1: Build loop ===
        build_loop = 0
        last_build_error = ""
        build_passed = False

        while build_loop < self.config.max_build_fix_loops:
            build_loop += 1
            build_ok, build_output = await self.pool.cargo_build(slot)

            if build_ok:
                await self._gate("Build", True, "PASS", pr=pr_number, connector=connector)
                build_passed = True
                break
            else:
                await self._gate(f"Build (loop {build_loop})", False, build_output[:200], pr=pr_number, connector=connector, output=build_output)
                last_build_error = build_output

                if build_loop < self.config.max_build_fix_loops:
                    fix_result = await resolver.run_fix_loop(
                        connector, threads, build_output, build_loop, pr_number=pr_number,
                    )
                    if fix_result.error:
                        display_error(f"Build fix loop {build_loop} failed: {fix_result.error}")
                        break

        if not build_passed:
            display_error(f"Build phase exhausted for {connector} after {build_loop} attempts")
            await self.pool.git_revert_all(slot)
            await self._emit("subtask_failed", pr=pr_number, connector=connector, error=f"Build failed after {build_loop} loops: {last_build_error[:200]}")
            for t in threads:
                self.state.mark_failed(t.thread_id, pr_number, f"Build failed: {last_build_error[:200]}")
            counts["failed"] = len(threads)
            return counts

        # === PHASE 2: Clippy loop ===
        clippy_loop = 0
        last_clippy_error = ""
        clippy_passed = False

        while clippy_loop < self.config.max_build_fix_loops:
            clippy_loop += 1
            clippy_ok, clippy_output = await self.pool.cargo_clippy(slot)

            if clippy_ok:
                await self._gate("Clippy", True, "PASS", pr=pr_number, connector=connector)
                clippy_passed = True
                break
            else:
                await self._gate(f"Clippy (loop {clippy_loop})", False, clippy_output[:200], pr=pr_number, connector=connector, output=clippy_output)
                last_clippy_error = clippy_output

                if clippy_loop < self.config.max_build_fix_loops:
                    fix_result = await resolver.run_fix_loop(
                        connector, threads, clippy_output, clippy_loop, pr_number=pr_number,
                    )
                    if fix_result.error:
                        display_error(f"Clippy fix loop {clippy_loop} failed: {fix_result.error}")
                        break

        if not clippy_passed:
            display_error(f"Clippy phase exhausted for {connector} after {clippy_loop} attempts")
            await self.pool.git_revert_all(slot)
            await self._emit("subtask_failed", pr=pr_number, connector=connector, error=f"Clippy failed after {clippy_loop} loops: {last_clippy_error[:200]}")
            for t in threads:
                self.state.mark_failed(t.thread_id, pr_number, f"Clippy failed: {last_clippy_error[:200]}")
            counts["failed"] = len(threads)
            return counts

        # === PHASE 3: Format (no loop) ===
        fmt_ok, fmt_output = await self.pool.cargo_fmt(slot)
        await self._gate("Format", fmt_ok, "PASS" if fmt_ok else fmt_output[:200], pr=pr_number, connector=connector)

        # Scope check: only connector files should have changed
        changed = await self.pool.git_changed_files(slot)
        unexpected = [f for f in changed if connector not in f]
        if unexpected:
            logger.warning("Unexpected files changed for %s: %s — reverting them", connector, unexpected)
            from .clone_pool import _run
            for f in unexpected:
                await _run(["git", "checkout", "--", f], slot.path)

        # Commit scoped to connector
        ok, stage_err = await self.pool.git_stage_connector(slot, connector)
        if not ok:
            display_error(f"git add failed: {stage_err}")
            counts["failed"] = len(threads)
            return counts

        instructions = "; ".join(t.instruction[:60] for t in threads[:3])
        commit_msg = f"fix({connector}): resolve {len(threads)} review comment(s)\n\n{instructions}"
        ok, sha = await self.pool.git_commit_connector(slot, connector, commit_msg)

        if ok:
            display_commit(sha, commit_msg.split("\n")[0])
            display_resolve_done(len(threads), 0, resolve_result.turn_count)
            await self._emit("subtask_committed", pr=pr_number, connector=connector, sha=sha)
            await self._emit("subtask_fixed", pr=pr_number, connector=connector)
            # Store per-comment summaries for individual replies
            per_thread = getattr(resolve_result, 'summaries_by_thread', {})
            for t in threads:
                self._resolve_summaries[t.thread_id] = per_thread.get(t.thread_id, resolve_result.summary)
            counts["fixed"] = len(threads)
        else:
            display_error(f"commit failed: {sha}")
            await self._emit("subtask_failed", pr=pr_number, connector=connector, error=f"commit failed: {sha}")
            counts["failed"] = len(threads)

        return counts

    # ------------------------------------------------------------------
    # Push + reply
    # ------------------------------------------------------------------

    async def _push_and_reply(
        self,
        slot: CloneSlot,
        branch: str,
        pr_number: int,
        threads: List[TriggeredThread],
        counts: Dict[str, int],
    ) -> None:
        """Push all commits and reply on fixed threads."""

        # GATE 5: Remote HEAD check
        from .clone_pool import _run
        await _run(["git", "fetch", "origin"], slot.path, timeout=60)

        # GATE 6: Threads still unresolved
        fresh = await self.github.fetch_pr_threads(pr_number)
        if fresh:
            resolved_ids = {rt.id for rt in fresh.threads if rt.is_resolved}
            still_open = [t for t in threads if t.thread_id not in resolved_ids]
            if not still_open:
                await self._gate("Threads still open (pre-push)", False, "all resolved externally", pr=pr_number)
                return
            await self._gate("Threads still open (pre-push)", True, f"{len(still_open)} open", pr=pr_number)

        # Push
        ok, push_err = await self.pool.git_push(slot, branch, pr_number=pr_number)
        if not ok:
            # Try rebase + retry
            await _run(["git", "pull", "--rebase", "origin", branch], slot.path, timeout=60)
            ok, push_err = await self.pool.git_push(slot, branch, pr_number=pr_number)

        if not ok:
            display_error(f"Push failed: {push_err}")
            await self._emit("pr_push_failed", pr=pr_number, error=push_err)
            return

        # Get final commit SHA
        _, sha, _ = await _run(["git", "rev-parse", "HEAD"], slot.path)
        sha = sha.strip()
        await self._emit("pr_pushed", pr=pr_number, sha=sha)

        # Reply on each fixed thread with what Claude actually did
        fixed_threads = [t for t in threads if not self.state.is_processed(t.thread_id)]
        for t in fixed_threads:
            summary = self._resolve_summaries.get(t.thread_id, "")
            if summary:
                # Use Claude's summary of what was changed (truncate to 500 chars)
                what_changed = summary[:500]
            else:
                what_changed = f"Applied fix for: {t.instruction[:200]}"
            body = f"**Resolved** in commit `{sha[:8]}`\n\n{what_changed}\n\n— *10xGrace*"
            posted = await self.github.post_thread_reply(t.thread_id, body)
            if posted:
                display_reply_posted(t.thread_id)
            summary = self._resolve_summaries.get(t.thread_id, "")
            self.state.mark_fixed(t.thread_id, pr_number, sha, t.path, t.instruction, resolution_summary=summary)
