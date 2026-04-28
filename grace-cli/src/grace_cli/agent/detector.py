"""Detects available AI agents (Claude Code, OpenCode)."""

import shutil
import subprocess
from typing import Optional, Dict, Any
from enum import Enum


class AgentType(Enum):
    """Types of AI agents supported."""
    CLAUDE_CODE = "claude_code"
    OPENCODE = "opencode"
    NONE = "none"


class AgentDetector:
    """Detects and validates available AI agents."""

    def detect(self) -> AgentType:
        """
        Detect the best available AI agent.

        Returns:
            AgentType: The detected agent type or NONE if none available.
        """
        # Check for Claude Code first (primary target)
        if self._has_claude_code():
            return AgentType.CLAUDE_CODE

        # Check for OpenCode
        if self._has_opencode():
            return AgentType.OPENCODE

        return AgentType.NONE

    def get_agent_info(self) -> Dict[str, Any]:
        """
        Get information about available agents.

        Returns:
            Dict with agent availability status.
        """
        return {
            "claude_code": {
                "available": self._has_claude_code(),
                "path": self._get_claude_code_path(),
            },
            "opencode": {
                "available": self._has_opencode(),
                "path": self._get_opencode_path(),
            },
        }

    def _has_claude_code(self) -> bool:
        """Check if Claude Code CLI is available."""
        return shutil.which("claude") is not None

    def _get_claude_code_path(self) -> Optional[str]:
        """Get the path to Claude Code binary."""
        return shutil.which("claude")

    def _has_opencode(self) -> bool:
        """Check if OpenCode is available."""
        # OpenCode detection - check for opencode binary or Python module
        if shutil.which("opencode") is not None:
            return True

        # Also check if running inside OpenCode context
        try:
            # This is a heuristic - presence of certain env vars
            import os
            if os.environ.get("OPENCODE_SESSION") or os.environ.get("OPENCODE_CONTEXT"):
                return True
        except Exception:
            pass

        return False

    def _get_opencode_path(self) -> Optional[str]:
        """Get the path to OpenCode binary."""
        return shutil.which("opencode")

    def validate_claude_code(self) -> tuple[bool, Optional[str]]:
        """
        Validate Claude Code is properly installed and authenticated.

        Returns:
            Tuple of (is_valid, error_message)
        """
        claude_path = self._get_claude_code_path()
        if not claude_path:
            return False, "Claude Code not found in PATH"

        try:
            # Try to run claude --version to verify it works
            result = subprocess.run(
                [claude_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return False, f"Claude Code returned error: {result.stderr}"

            return True, None

        except subprocess.TimeoutExpired:
            return False, "Claude Code timed out (may need authentication)"
        except Exception as e:
            return False, f"Failed to run Claude Code: {str(e)}"
