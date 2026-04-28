"""Invokes AI agents to generate tech specs."""

import subprocess
import os
from typing import Dict, Any, Optional, Callable
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .detector import AgentDetector, AgentType
from .fallback import FallbackHandler

console = Console()


class AgentInvoker:
    """Invokes AI agents to perform connector generation tasks."""

    def __init__(self):
        self.detector = AgentDetector()
        self.fallback = FallbackHandler()

    def invoke_techspec_generation(
        self,
        context: Dict[str, Any],
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """
        Invoke AI agent to generate tech spec.

        Args:
            context: Collected wizard context.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dict with result status and details.
        """
        agent_type = self.detector.detect()

        if progress_callback:
            progress_callback(f"Detected agent: {agent_type.value}")

        if agent_type == AgentType.CLAUDE_CODE:
            return self._invoke_claude_code(context, progress_callback)
        elif agent_type == AgentType.OPENCODE:
            return self._invoke_opencode(context, progress_callback)
        else:
            return self._handle_fallback(context)

    def _invoke_claude_code(
        self,
        context: Dict[str, Any],
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """Invoke Claude Code CLI to generate tech spec."""
        connector_name = context["connector_name"]
        doc_source = context.get("doc_source", {})

        # Build the prompt for Claude Code
        prompt = self._build_agent_prompt(context)

        # Determine allowed tools based on doc source
        allowed_tools = "Read,Write,Edit,Bash,WebFetch,Glob,Grep"

        # Build command
        cmd = [
            "claude",
            "-p", prompt,
            "--allowedTools", allowed_tools,
            "--add-dir", str(Path.cwd()),
        ]

        console.print(f"\n[cyan]Invoking Claude Code for {connector_name}...[/cyan]")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(
                    "Generating tech spec with Claude Code...",
                    total=None
                )

                # Run Claude Code
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # 1 hour timeout for large docs
                    cwd=str(Path.cwd())
                )

                progress.update(task, completed=True)

            if result.returncode == 0:
                return {
                    "success": True,
                    "agent": "claude_code",
                    "output": result.stdout,
                    "connector": connector_name.lower(),
                    "output_path": f"grace-cli/.grace/{connector_name.lower()}/technical_specification.md"
                }
            else:
                return {
                    "success": False,
                    "agent": "claude_code",
                    "error": result.stderr or "Unknown error",
                    "stdout": result.stdout,
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "agent": "claude_code",
                "error": "Claude Code timed out after 1 hour",
            }
        except Exception as e:
            return {
                "success": False,
                "agent": "claude_code",
                "error": f"Failed to invoke Claude Code: {str(e)}",
            }

    def _invoke_opencode(
        self,
        context: Dict[str, Any],
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """Invoke OpenCode to generate tech spec."""
        # OpenCode integration - placeholder for now
        # This would use OpenCode's API if available
        console.print("\n[yellow]OpenCode integration coming soon.[/yellow]")
        return self._handle_fallback(context)

    def _handle_fallback(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle case when no AI agent is available."""
        return self.fallback.show_instructions(context)

    def _build_agent_prompt(self, context: Dict[str, Any]) -> str:
        """Build the prompt for the AI agent."""
        connector = context["connector_name"]
        doc_source = context.get("doc_source", {})

        # Base prompt
        prompt_parts = [
            f"You are implementing a payment connector for Hyperswitch.",
            f"",
            f"CONNECTOR NAME: {connector}",
            f"BASE URL: {context.get('base_url', 'N/A')}",
            f"AUTHENTICATION TYPE: {context.get('auth_type', 'N/A')}",
            f"",
            f"SUPPORTED FLOWS:",
        ]

        for flow in context.get("flows", []):
            prompt_parts.append(f"  - {flow}")

        prompt_parts.extend([
            f"",
            f"SUPPORTED PAYMENT METHODS:",
        ])

        for method in context.get("payment_methods", []):
            prompt_parts.append(f"  - {method}")

        # Add pre-auth requirements if any
        pre_auth = context.get("pre_auth_requirements", [])
        if pre_auth:
            prompt_parts.extend([
                f"",
                f"PRE-AUTHORIZATION REQUIREMENTS:",
            ])
            for req in pre_auth:
                prompt_parts.append(f"  - {req}")

        # Add webhook info
        webhooks = context.get("webhooks", {})
        if webhooks.get("enabled"):
            prompt_parts.extend([
                f"",
                f"WEBHOOK SUPPORT: Yes",
                f"SIGNATURE METHOD: {webhooks.get('signature_method', 'none')}",
            ])

        # Add documentation source
        prompt_parts.extend([
            f"",
            f"DOCUMENTATION SOURCE:",
            f"  Type: {doc_source.get('type', 'N/A')}",
        ])

        if doc_source.get("type") == "folder":
            prompt_parts.append(f"  Path: {doc_source.get('path', 'N/A')}")
        elif doc_source.get("type") == "urls":
            prompt_parts.append(f"  URLs file: {doc_source.get('path', 'N/A')}")

        # Task instructions
        prompt_parts.extend([
            f"",
            f"YOUR TASK:",
            f"Generate a complete technical specification for the {connector} connector.",
            f"",
            f"STEPS:",
            f"1. Read and analyze the provided documentation",
            f"2. Identify all API endpoints for the supported flows",
            f"3. Map payment methods to Hyperswitch types",
            f"4. Document authentication mechanisms",
            f"5. Create a comprehensive technical specification",
            f"",
            f"OUTPUT:",
            f"Save the technical specification to:",
            f"  grace-cli/.grace/{connector.lower()}/technical_specification.md",
            f"",
            f"Use the pattern guides in grace/rulesbook/codegen/guides/patterns/ as reference.",
            f"Follow the structure from existing connector specifications.",
        ])

        return "\n".join(prompt_parts)
