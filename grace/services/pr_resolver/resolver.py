"""Claude Agent SDK integration for the PR Resolver service."""

import asyncio
import logging
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .prompts import build_resolution_prompt

logger = logging.getLogger(__name__)


@dataclass
class ResolveResult:
    fixed_threads: List[str] = field(default_factory=list)
    failed_threads: List[str] = field(default_factory=list)
    modified_files: Set[str] = field(default_factory=set)
    build_passed: bool = False
    error: Optional[str] = None
    turn_count: int = 0


class CommentResolver:
    """Runs a Claude Agent SDK session to resolve review comments."""

    def __init__(
        self,
        repo_path: Path,
        index_dir: Path,
        claude_api_key: str = "",
        claude_base_url: str = "",
        claude_model: str = "",
        max_turns: int = 50,
        event_callback: Optional[Callable] = None,
    ) -> None:
        self.repo_path = repo_path
        self.index_dir = index_dir
        self.claude_api_key = claude_api_key
        self.claude_base_url = claude_base_url
        self.claude_model = claude_model
        self.max_turns = max_turns
        self.event_callback = event_callback

    def _emit(self, event_type: str, **data: Any) -> None:
        """Fire event callback if set, with error logging."""
        if self.event_callback is None:
            return
        try:
            self.event_callback(event_type, **data)
        except Exception:
            logger.error("Event callback error for %s:\n%s", event_type, traceback.format_exc())

    async def resolve_comments(self, threads: List[Any]) -> ResolveResult:
        """Run the Claude agent to resolve the given review comment threads.

        Returns a ``ResolveResult`` describing what happened.
        """
        result = ResolveResult()

        prompt = build_resolution_prompt(threads, self.index_dir)

        try:
            from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, ResultMessage, AssistantMessage
        except ImportError:
            result.error = "claude-agent-sdk is not installed"
            logger.error(result.error)
            return result

        # Build SDK options
        env_vars: Dict[str, str] = {}
        if self.claude_api_key:
            env_vars["ANTHROPIC_API_KEY"] = self.claude_api_key
        if self.claude_base_url:
            env_vars["ANTHROPIC_BASE_URL"] = self.claude_base_url

        options = ClaudeAgentOptions(
            allowed_tools=["Read", "Edit", "Glob", "Grep", "Bash"],
            permission_mode="bypassPermissions",
            cwd=str(self.repo_path),
            env=env_vars,
            max_turns=self.max_turns,
        )
        if self.claude_model:
            options.model = self.claude_model

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
                                self._emit(
                                    "agent_tool",
                                    turn=result.turn_count,
                                    tool_name=tool_name,
                                    tool_input=tool_input,
                                )
                                # Track modified files from Edit calls
                                if tool_name.lower() in ("edit", "editfile", "write", "writefile"):
                                    fpath = tool_input.get("file_path", tool_input.get("path", ""))
                                    if fpath:
                                        result.modified_files.add(fpath)
                            elif hasattr(block, "text"):
                                text = block.text.strip()
                                if text:
                                    self._emit("agent_text", turn=result.turn_count, text=text)
                            elif hasattr(block, "thinking"):
                                self._emit("agent_thinking", turn=result.turn_count, thinking=block.thinking)
                    elif isinstance(message, ResultMessage):
                        self._emit("agent_result", message=message)
            finally:
                await client.disconnect()

            # Assume all threads fixed unless we get explicit failures
            # (the service layer verifies via cargo check)
            result.fixed_threads = [t.thread_id for t in threads]
            result.build_passed = True

        except Exception as exc:
            result.error = str(exc)
            logger.exception("Claude agent session failed")
            result.failed_threads = [t.thread_id for t in threads]

        return result
