"""Wizard flow orchestration."""

from typing import Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from .prompts import WizardPrompts

console = Console()


class WizardRunner:
    """Runs the interactive wizard and collects connector context."""

    def __init__(self):
        self.prompts = WizardPrompts()
        self.context: Dict[str, Any] = {}

    def run(self) -> Optional[Dict[str, Any]]:
        """Run the complete wizard flow and return collected context."""
        try:
            self._display_header()

            # Step 1: Connector Information
            self._step_connector_info()

            # Step 2: Documentation
            self._step_documentation()

            # Step 3: Payment Flows
            self._step_payment_flows()

            # Step 4: Payment Methods
            self._step_payment_methods()

            # Step 5: Pre-Auth Requirements
            self._step_pre_auth()

            # Step 6: Webhook Support
            self._step_webhooks()

            # Step 7: Confirm and Proceed
            if not self._confirm_and_proceed():
                console.print("\n[yellow]Cancelled by user.[/yellow]")
                return None

            return self.context

        except KeyboardInterrupt:
            console.print("\n\n[red]Wizard interrupted by user.[/red]")
            return None
        except Exception as e:
            console.print(f"\n[red]Error during wizard: {str(e)}[/red]")
            return None

    def _display_header(self) -> None:
        """Display the wizard header."""
        header = Text()
        header.append("╔═══════════════════════════════════════════════════╗\n", style="blue")
        header.append("║  ", style="blue")
        header.append("Grace", style="bold cyan")
        header.append(" - Hyperswitch Connector Generator", style="white")
        header.append("        ║\n", style="blue")
        header.append("╚═══════════════════════════════════════════════════╝", style="blue")
        console.print(header)
        console.print("\n[dim]This wizard will guide you through creating a payment connector.[/dim]\n")

    def _step_connector_info(self) -> None:
        """Step 1: Collect connector basic information."""
        console.print("\n[bold blue]Step 1/6:[/bold blue] Connector Information")
        console.print("─" * 50)

        self.context["connector_name"] = self.prompts.ask_connector_name()
        self.context["base_url"] = self.prompts.ask_base_url()
        self.context["auth_type"] = self.prompts.ask_auth_type()

    def _step_documentation(self) -> None:
        """Step 2: Collect documentation source."""
        console.print("\n[bold blue]Step 2/6:[/bold blue] Documentation")
        console.print("─" * 50)

        doc_source = self.prompts.ask_documentation_source()
        self.context["doc_source"] = doc_source

    def _step_payment_flows(self) -> None:
        """Step 3: Collect supported payment flows."""
        console.print("\n[bold blue]Step 3/6:[/bold blue] Payment Flows")
        console.print("─" * 50)
        console.print("[dim]Select all payment flows supported by this connector[/dim]")

        self.context["flows"] = self.prompts.ask_payment_flows()

    def _step_payment_methods(self) -> None:
        """Step 4: Collect supported payment methods."""
        console.print("\n[bold blue]Step 4/6:[/bold blue] Payment Methods")
        console.print("─" * 50)
        console.print("[dim]Select all payment methods supported by this connector[/dim]")

        self.context["payment_methods"] = self.prompts.ask_payment_methods()

    def _step_pre_auth(self) -> None:
        """Step 5: Collect pre-authorization requirements."""
        console.print("\n[bold blue]Step 5/6:[/bold blue] Pre-Authorization Requirements")
        console.print("─" * 50)
        console.print("[dim]Some connectors require setup before payment authorization[/dim]")

        self.context["pre_auth_requirements"] = self.prompts.ask_pre_auth_requirements()

    def _step_webhooks(self) -> None:
        """Step 6: Collect webhook configuration."""
        console.print("\n[bold blue]Step 6/6:[/bold blue] Webhook Configuration")
        console.print("─" * 50)

        self.context["webhooks"] = self.prompts.ask_webhook_support()

    def _confirm_and_proceed(self) -> bool:
        """Display summary and confirm with user."""
        return self.prompts.confirm_proceed(
            self.context["connector_name"],
            {
                "base_url": self.context["base_url"],
                "auth_type": self.context["auth_type"],
                "flows": self.context["flows"],
                "payment_methods": self.context["payment_methods"],
            }
        )
