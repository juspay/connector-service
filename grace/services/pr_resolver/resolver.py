"""Claude Agent SDK integration for the PR Resolver service.

Runs per-connector Claude sessions and handles build-fix loops.
"""

import asyncio
import logging
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .prompts import build_fix_loop_prompt

logger = logging.getLogger(__name__)


@dataclass
class ResolveResult:
    fixed_threads: List[str] = field(default_factory=list)
    failed_threads: List[str] = field(default_factory=list)
    modified_files: Set[str] = field(default_factory=set)
    build_passed: bool = False
    clippy_passed: bool = False
    summary: str = ""  # Claude's final summary of what was changed
    error: Optional[str] = None
    turn_count: int = 0
    loop_count: int = 0


class CommentResolver:
    """Runs Claude Agent SDK sessions to resolve review comments.

    One session per connector sub-task. Supports build-fix loops where
    build/clippy errors are fed back to Claude for correction.
    """

    def __init__(
        self,
        repo_path: Path,
        index_dir: Path,
        claude_api_key: str = "",
        claude_base_url: str = "",
        claude_model: str = "",
        max_turns: int = 20,
        event_callback: Optional[Callable] = None,
    ) -> None:
        self.repo_path = repo_path
        self.index_dir = index_dir
        self.claude_api_key = claude_api_key
        self.claude_base_url = claude_base_url
        self.claude_model = claude_model
        self.max_turns = max_turns
        self.event_callback = event_callback

    async def _emit(self, event_type: str, **data: Any) -> None:
        """Fire event callback (async-safe)."""
        if self.event_callback is None:
            return
        try:
            result = self.event_callback(event_type, **data)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            logger.error("Event callback error for %s:\n%s", event_type, traceback.format_exc())

    def _build_sdk_options(self):
        """Build ClaudeAgentOptions for a session."""
        try:
            from claude_agent_sdk import ClaudeAgentOptions
        except ImportError as e:
            raise ImportError("claude-agent-sdk is not installed") from e

        env_vars: Dict[str, str] = {}
        if self.claude_api_key:
            env_vars["ANTHROPIC_API_KEY"] = self.claude_api_key
        if self.claude_base_url:
            env_vars["ANTHROPIC_BASE_URL"] = self.claude_base_url

        options = ClaudeAgentOptions(
            allowed_tools=["Read", "Edit", "Glob", "Grep", "Bash", "Agent"],
            permission_mode="bypassPermissions",
            cwd=str(self.repo_path),
            env=env_vars,
            max_turns=self.max_turns,
        )
        if self.claude_model:
            options.model = self.claude_model
        return options

    async def _run_claude_session(
        self,
        prompt: str,
        connector: str = "",
        pr_number: int = 0,
    ) -> ResolveResult:
        """Run a single Claude Agent SDK session with the given prompt.

        Returns a ResolveResult with modified files and turn count.
        """
        result = ResolveResult()

        try:
            from claude_agent_sdk import ClaudeSDKClient, ResultMessage, AssistantMessage
        except ImportError:
            result.error = "claude-agent-sdk is not installed"
            return result

        options = self._build_sdk_options()

        try:
            client = ClaudeSDKClient(options)
            await client.connect()

            try:
                await client.query(prompt)
                async for message in client.receive_response():
                    if isinstance(message, AssistantMessage):
                        result.turn_count += 1
                        for block in message.content:
                            if hasattr(block, "name") and hasattr(block, "input"):
                                tool_name = block.name
                                tool_input = block.input or {}
                                await self._emit(
                                    "subtask_agent_tool",
                                    pr=pr_number,
                                    connector=connector,
                                    turn=result.turn_count,
                                    tool=tool_name,
                                    input_summary=str(
                                        tool_input.get("file_path",
                                        tool_input.get("path",
                                        tool_input.get("command", "")))
                                    )[:120],
                                )
                                # Track modified files
                                if tool_name.lower() in ("edit", "editfile", "write", "writefile"):
                                    fpath = tool_input.get("file_path", tool_input.get("path", ""))
                                    if fpath:
                                        result.modified_files.add(fpath)

                            elif hasattr(block, "text"):
                                text = block.text.strip()
                                if text:
                                    result.summary = text  # Keep last text as summary
                                    await self._emit(
                                        "subtask_agent_text",
                                        pr=pr_number,
                                        connector=connector,
                                        turn=result.turn_count,
                                        text=text[:200],
                                    )
                    elif isinstance(message, ResultMessage):
                        pass  # Session complete
            finally:
                await client.disconnect()

            result.fixed_threads = []  # Caller determines this
            result.build_passed = True  # Tentative — caller verifies

        except Exception as exc:
            result.error = str(exc)
            logger.exception("Claude agent session failed for connector=%s", connector)

        return result

    async def resolve_single_comment(
        self,
        thread: Any,
        connector_name: str,
        pr_number: int = 0,
    ) -> ResolveResult:
        """Resolve ONE review comment. Returns result with per-comment summary."""
        prompt = f"""You are fixing ONE review comment on connector `{connector_name}`.

**File:** `{thread.path}`
**Line:** {thread.line or '?'}
**Reviewer:** @{thread.author}
**Instruction:** {thread.instruction}

**Code context:**
```diff
{thread.diff_hunk}
```

## Steps
1. Read the file `{thread.path}` to understand the context around line {thread.line or '?'}
2. Make the MINIMAL edit that addresses the reviewer's feedback
3. ONLY modify files under `connectors/{connector_name}/` or `connectors/{connector_name}.rs`
4. Use RELATIVE paths — never absolute paths starting with /Users/

## Output
After making your edit, write a **1-2 sentence summary** of exactly what you changed and why. This summary will be posted as a reply on the GitHub PR comment.

Do NOT run cargo build — the service verifies externally.
"""
        # Strip absolute paths
        import re
        prompt = re.sub(r'/Users/[^\s\]\)"]+/', '', prompt)

        result = await self._run_claude_session(prompt, connector=connector_name, pr_number=pr_number)
        result.fixed_threads = [thread.thread_id]
        return result

    async def resolve_connector(
        self,
        connector_name: str,
        threads: List[Any],
        pr_number: int = 0,
    ) -> ResolveResult:
        """Resolve all comments for one connector — one subagent session per comment.

        Processes comments sequentially (same file, edits must not conflict).
        Each comment gets its own Claude session and its own summary.
        """
        await self._emit("subtask_start", pr=pr_number, connector=connector_name, comment_count=len(threads))

        combined = ResolveResult()
        combined.summaries_by_thread = {}  # type: dict  # thread_id -> summary

        for i, thread in enumerate(threads):
            await self._emit("subtask_agent_text", pr=pr_number, connector=connector_name,
                             turn=0, text=f"Resolving comment {i+1}/{len(threads)}: {thread.instruction[:60]}")

            result = await self.resolve_single_comment(thread, connector_name, pr_number)

            if result.error:
                combined.error = result.error
                combined.failed_threads.append(thread.thread_id)
            else:
                combined.fixed_threads.append(thread.thread_id)
                combined.modified_files.update(result.modified_files)
                combined.summaries_by_thread[thread.thread_id] = result.summary

            combined.turn_count += result.turn_count

        # Build a combined summary
        parts = []
        for t in threads:
            s = combined.summaries_by_thread.get(t.thread_id, "")
            if s:
                parts.append(f"- L{t.line}: {s[:200]}")
        combined.summary = "\n".join(parts) if parts else ""

        return combined

    async def run_fix_loop(
        self,
        connector_name: str,
        threads: List[Any],
        error_output: str,
        loop_iteration: int,
        pr_number: int = 0,
    ) -> ResolveResult:
        """Run a build-fix loop iteration.

        Called by the service when cargo build or clippy fails after the initial fix.
        Sends the error output back to Claude with context about the original comments.
        """
        await self._emit(
            "subtask_gate",
            pr=pr_number,
            connector=connector_name,
            gate=f"Build-fix loop {loop_iteration}",
            passed=False,
            detail="Sending errors back to Claude",
        )

        prompt = build_fix_loop_prompt(threads, error_output, loop_iteration, connector_name=connector_name)
        result = await self._run_claude_session(prompt, connector=connector_name, pr_number=pr_number)
        result.loop_count = loop_iteration
        result.fixed_threads = [t.thread_id for t in threads]
        return result
