"""Grace CLI - Main entry point for the grace command."""

import sys
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .wizard.runner import WizardRunner
from .agent.invoker import AgentInvoker
from .agent.detector import AgentDetector, AgentType

console = Console()


def print_banner():
    """Print the Grace CLI banner."""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════════════════════╗\n", style="blue")
    banner.append("║  ", style="blue")
    banner.append("Grace", style="bold bright_cyan")
    banner.append(" - ", style="white")
    banner.append("Hyperswitch", style="bold bright_blue")
    banner.append(" Connector Generator", style="white")
    banner.append("        ║\n", style="blue")
    banner.append("╚═══════════════════════════════════════════════════════════╝", style="blue")
    console.print(banner)


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version="0.1.0", prog_name="grace")
def cli(ctx):
    """
    Grace CLI - Generate Hyperswitch payment connectors.

    This tool helps you create new payment processor integrations
    for Hyperswitch through an interactive wizard.

    \b
    Commands:
      create    Create a new connector interactively
      status    Check available AI agents

    \b
    Examples:
      grace create              # Start interactive wizard
      grace status              # Check agent availability
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("\n[dim]Run 'grace create' to start creating a connector.[/dim]")
        console.print("Run 'grace --help' for more information.\n")


@cli.command()
def create():
    """
    Create a new payment connector.

    Launches an interactive wizard to collect connector requirements,
    then invokes an AI agent to generate the technical specification.
    """
    print_banner()

    # Run wizard to collect context
    runner = WizardRunner()
    context = runner.run()

    if not context:
        sys.exit(1)

    # Invoke AI agent
    console.print("\n")
    invoker = AgentInvoker()
    result = invoker.invoke_techspec_generation(context)

    # Display result
    _display_result(result)


def _display_result(result: dict):
    """Display the result of agent invocation."""
    console.print("\n")

    if result.get("success"):
        console.print(Panel(
            f"[bold green]✓ Tech spec generated successfully![/bold green]\n\n"
            f"Connector: [cyan]{result.get('connector', 'N/A')}[/cyan]\n"
            f"Agent: [dim]{result.get('agent', 'N/A')}[/dim]\n\n"
            f"Output:\n"
            f"[bright_black]{result.get('output_path', 'N/A')}[/bright_black]",
            title="Success",
            border_style="green"
        ))

        console.print("\n[bold]Next Steps:[/bold]")
        console.print("─" * 60)
        console.print("1. Review the generated tech spec")
        console.print("2. Generate the full connector code:")
        console.print(f"   [dim]$ claude -p \"integrate {result.get('connector', 'Connector')} using grace-cli/.gracerules\"[/dim]")
        console.print("")

    elif result.get("fallback"):
        # Fallback was shown - nothing more to do
        console.print("\n[dim]Follow the instructions above to generate the tech spec manually.[/dim]\n")

    else:
        console.print(Panel(
            f"[bold red]✗ Failed to generate tech spec[/bold red]\n\n"
            f"Agent: {result.get('agent', 'N/A')}\n"
            f"Error: {result.get('error', 'Unknown error')}",
            title="Error",
            border_style="red"
        ))
        sys.exit(1)


@cli.command()
def status():
    """
    Check available AI agents.

    Detects and reports which AI agents are available for connector generation.
    """
    print_banner()
    console.print("\n[bold]Checking available AI agents...[/bold]\n")

    detector = AgentDetector()
    agent_info = detector.get_agent_info()

    # Claude Code
    claude_available = agent_info["claude_code"]["available"]
    claude_path = agent_info["claude_code"]["path"]

    if claude_available:
        console.print("[green]✓[/green] Claude Code detected")
        console.print(f"   Path: [dim]{claude_path}[/dim]")

        # Validate it works
        is_valid, error = detector.validate_claude_code()
        if is_valid:
            console.print("   Status: [green]Ready to use[/green]")
        else:
            console.print(f"   Status: [yellow]Available but may need authentication[/yellow]")
            if error:
                console.print(f"   Note: [dim]{error}[/dim]")
    else:
        console.print("[red]✗[/red] Claude Code not found")
        console.print("   [dim]Install: curl -fsSL https://claude.ai/install.sh | bash[/dim]")

    console.print("")

    # OpenCode
    opencode_available = agent_info["opencode"]["available"]
    opencode_path = agent_info["opencode"]["path"]

    if opencode_available:
        console.print("[green]✓[/green] OpenCode detected")
        if opencode_path:
            console.print(f"   Path: [dim]{opencode_path}[/dim]")
    else:
        console.print("[dim]○ OpenCode not detected (optional)[/dim]")

    console.print("")

    # Overall status
    detected = detector.detect()
    if detected != AgentType.NONE:
        console.print(f"[green]✓ AI agent available: {detected.value}[/green]")
        console.print("\nYou can run [bold]grace create[/bold] to start generating connectors.\n")
    else:
        console.print("[yellow]⚠ No AI agents detected[/yellow]")
        console.print("\ngrace create will show manual instructions instead.")
        console.print("Install Claude Code for automated generation:\n")
        console.print("  [dim]curl -fsSL https://claude.ai/install.sh | bash[/dim]\n")


def main():
    """Main entry point for Grace CLI."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n\n[red]Interrupted by user.[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
