"""Rich console display helpers for the PR Resolver service."""

import logging
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Try to reuse the shared Claude display helpers
# ---------------------------------------------------------------------------

try:
    from src.workflows.techspec.nodes._claude_display import (
        display_tool_use,
        display_text,
        display_thinking,
        display_result,
    )
except ImportError:
    # Fallback implementations
    def display_tool_use(turn: int, tool_name: str, tool_input: dict) -> None:
        summary = str(tool_input)[:100]
        console.print(f"  [dim]Turn {turn}[/dim]  [bold yellow]{tool_name}[/bold yellow]  [dim]{summary}[/dim]")

    def display_text(turn: int, text: str) -> None:
        preview = text.replace("\n", " ").strip()[:120]
        console.print(f"  [dim]Turn {turn}[/dim]  [green]text[/green] {preview}")

    def display_thinking(turn: int, thinking: str) -> None:
        preview = thinking.replace("\n", " ").strip()[:120]
        console.print(f"  [dim]Turn {turn}[/dim]  [magenta]thinking[/magenta] [dim]{preview}[/dim]")

    def display_result(result_msg: Any) -> None:
        console.print("  [bold green]Result[/bold green]  done")


# ---------------------------------------------------------------------------
# Service-specific display functions
# ---------------------------------------------------------------------------


def display_cycle_start(cycle: int) -> None:
    console.print()
    console.rule(f"[bold cyan]Poll Cycle {cycle}[/bold cyan]")
    console.print()


def display_no_comments() -> None:
    console.print("  [dim]No triggered comments found this cycle.[/dim]")


def display_pr_processing(pr_number: int, branch: str, thread_count: int) -> None:
    console.print(
        f"\n  [bold]PR #{pr_number}[/bold] [dim]({branch})[/dim] — "
        f"{thread_count} comment{'s' if thread_count != 1 else ''} to resolve"
    )


def display_gate(name: str, passed: bool, detail: str = "") -> None:
    icon = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
    suffix = f"  [dim]{detail}[/dim]" if detail else ""
    console.print(f"    Gate [{name}]: {icon}{suffix}")


def display_resolving(thread_count: int) -> None:
    console.print(f"\n    [bold cyan]Resolving {thread_count} comment{'s' if thread_count != 1 else ''}...[/bold cyan]")


def display_resolve_done(fixed: int, failed: int, turns: int) -> None:
    console.print(
        f"    [bold]Resolution complete:[/bold] "
        f"[green]{fixed} fixed[/green], [red]{failed} failed[/red] "
        f"({turns} turns)"
    )


def display_commit(sha: str, message: str) -> None:
    console.print(f"    [green]Committed:[/green] {sha[:8]} — {message}")


def display_reply_posted(thread_id: str) -> None:
    console.print(f"    [dim]Reply posted on thread {thread_id[:12]}...[/dim]")


def display_error(message: str) -> None:
    console.print(f"  [bold red]Error:[/bold red] {message}")


def display_skip(thread_id: str, reason: str) -> None:
    console.print(f"    [yellow]Skip[/yellow] {thread_id[:12]}... — {reason}")


def display_cycle_summary(
    cycle: int,
    total: int,
    fixed: int,
    failed: int,
    skipped: int,
) -> None:
    """Print a Rich table summarising the cycle."""
    table = Table(title=f"Cycle {cycle} Summary", show_header=True, header_style="bold")
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right")
    table.add_row("Total comments", str(total))
    table.add_row("Fixed", f"[green]{fixed}[/green]")
    table.add_row("Failed", f"[red]{failed}[/red]")
    table.add_row("Skipped", f"[yellow]{skipped}[/yellow]")
    console.print(table)


def display_comment_list(comments: List[Dict[str, Any]]) -> None:
    """Print a Rich table listing triggered comments."""
    table = Table(title="Triggered Comments", show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=5)
    table.add_column("File")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Reviewer", width=14)
    table.add_column("Instruction")

    for i, c in enumerate(comments, 1):
        table.add_row(
            str(i),
            c.get("path", ""),
            str(c.get("line", "")),
            c.get("author", ""),
            (c.get("instruction", ""))[:80],
        )

    console.print(table)
