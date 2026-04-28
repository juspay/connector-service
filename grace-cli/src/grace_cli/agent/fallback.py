"""Fallback handler when no AI agent is available."""

from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


class FallbackHandler:
    """Handles fallback to manual instructions when no AI agent is available."""

    def show_instructions(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Display manual instructions for the user.

        Args:
            context: Collected wizard context.

        Returns:
            Dict indicating fallback mode with instructions.
        """
        connector = context["connector_name"]
        doc_source = context.get("doc_source", {})

        console.print("\n")
        console.print(Panel(
            "[yellow]No AI agent detected[/yellow]\n\n"
            "Claude Code is not installed or not in PATH.\n"
            "Please run the command below manually in your AI coding agent.",
            title="⚠️  Manual Action Required",
            border_style="yellow"
        ))

        # Option 1: Full workflow command
        console.print("\n[bold cyan]Option 1: Use Grace workflow (Recommended)[/bold cyan]")
        console.print("─" * 60)
        cmd1 = f"integrate {connector} using grace-cli/.gracerules"
        console.print(Syntax(cmd1, "bash", theme="monokai", line_numbers=False))

        # Option 2: Tech spec only
        console.print("\n[bold cyan]Option 2: Generate tech spec only[/bold cyan]")
        console.print("─" * 60)

        if doc_source.get("type") == "folder":
            cmd2 = f"grace techspec {connector} -f {doc_source.get('path')} -v"
        elif doc_source.get("type") == "urls":
            cmd2 = f"grace techspec {connector} -u {doc_source.get('path')} -v"
        else:
            cmd2 = f"grace techspec {connector} -v"

        console.print(Syntax(cmd2, "bash", theme="monokai", line_numbers=False))

        # Show context summary
        console.print("\n[bold cyan]Connector Context:[/bold cyan]")
        console.print("─" * 60)

        context_table = f"""Connector: {connector}
Base URL: {context.get('base_url', 'N/A')}
Auth: {context.get('auth_type', 'N/A')}
Flows: {', '.join(context.get('flows', []))}
Methods: {', '.join(context.get('payment_methods', []))}"""

        console.print(Panel(context_table, border_style="dim"))

        # Installation instructions
        console.print("\n[bold cyan]Install Claude Code:[/bold cyan]")
        console.print("─" * 60)
        console.print(Syntax(
            "curl -fsSL https://claude.ai/install.sh | bash",
            "bash",
            theme="monokai",
            line_numbers=False
        ))
        console.print("[dim]Or visit: https://claude.ai/code[/dim]")

        return {
            "success": False,
            "fallback": True,
            "agent": "none",
            "instructions_shown": True,
            "connector": connector.lower(),
        }
