"""Interactive prompts for the Grace wizard."""

from typing import List, Dict, Any, Optional
import questionary
from questionary import Choice


class WizardPrompts:
    """Collection of interactive prompts for connector creation."""

    @staticmethod
    def ask_connector_name() -> str:
        """Ask for connector name."""
        return questionary.text(
            "Connector name (PascalCase, e.g., StripeClone, MyPayment):",
            validate=lambda text: (
                len(text) > 0 and text[0].isupper()
            ) or "Name must start with uppercase and be non-empty",
        ).ask()

    @staticmethod
    def ask_base_url() -> str:
        """Ask for API base URL."""
        return questionary.text(
            "Base API URL (e.g., https://api.stripe.com/v1):",
            validate=lambda text: (
                text.startswith("http://") or text.startswith("https://")
            ) or "URL must start with http:// or https://",
        ).ask()

    @staticmethod
    def ask_auth_type() -> str:
        """Ask for authentication type."""
        return questionary.select(
            "Authentication type:",
            choices=[
                Choice("API Key", value="api_key"),
                Choice("OAuth 2.0", value="oauth2"),
                Choice("Basic Auth", value="basic_auth"),
                Choice("Custom", value="custom"),
            ],
        ).ask()

    @staticmethod
    def ask_documentation_source() -> Dict[str, Any]:
        """Ask how documentation will be provided."""
        source = questionary.select(
            "How do you want to provide API documentation?",
            choices=[
                Choice("Local folder (PDF/Markdown/HTML)", value="folder"),
                Choice("Website URLs to scrape", value="urls"),
                Choice("Manually describe endpoints", value="manual"),
            ],
        ).ask()

        if source == "folder":
            path = questionary.path(
                "Path to documentation folder:",
                only_directories=True,
            ).ask()
            return {"type": "folder", "path": path}

        elif source == "urls":
            urls_path = questionary.path(
                "Path to file containing URLs (one per line):",
            ).ask()
            return {"type": "urls", "path": urls_path}

        else:
            return {"type": "manual", "description": None}

    @staticmethod
    def ask_payment_flows() -> List[str]:
        """Ask for supported payment flows."""
        flows = questionary.checkbox(
            "Select supported payment flows (space to toggle, enter to confirm):",
            choices=[
                Choice("Authorize", value="authorize", checked=True),
                Choice("Capture", value="capture", checked=True),
                Choice("Refund", value="refund", checked=True),
                Choice("Void", value="void"),
                Choice("Payment Sync (PSync)", value="psync", checked=True),
                Choice("Refund Sync (RSync)", value="rsync", checked=True),
                Choice("Webhooks", value="webhooks"),
                Choice("Setup Mandate", value="setup_mandate"),
                Choice("Repeat Payment", value="repeat_payment"),
            ],
        ).ask()
        return flows or []

    @staticmethod
    def ask_payment_methods() -> List[str]:
        """Ask for supported payment methods."""
        methods = questionary.checkbox(
            "Select supported payment methods (space to toggle, enter to confirm):",
            choices=[
                Choice("Credit Card", value="credit_card", checked=True),
                Choice("Debit Card", value="debit_card", checked=True),
                Choice("Apple Pay", value="apple_pay"),
                Choice("Google Pay", value="google_pay"),
                Choice("PayPal", value="paypal"),
                Choice("Bank Transfer (SEPA)", value="sepa"),
                Choice("Bank Transfer (ACH)", value="ach"),
                Choice("UPI", value="upi"),
                Choice("BNPL (Buy Now Pay Later)", value="bnpl"),
                Choice("Crypto", value="crypto"),
                Choice("Gift Card", value="gift_card"),
            ],
        ).ask()
        return methods or []

    @staticmethod
    def ask_pre_auth_requirements() -> List[str]:
        """Ask for pre-authorization requirements."""
        requirements = questionary.checkbox(
            "Pre-authorization requirements (skip if payment can be authorized directly):",
            choices=[
                Choice("Create Order/Intent before payment", value="create_order"),
                Choice("Create Customer before payment", value="create_customer"),
                Choice("Tokenize payment method", value="tokenize"),
                Choice("Server authentication (OAuth token)", value="server_auth"),
                Choice("Session token", value="session_token"),
            ],
        ).ask()
        return requirements or []

    @staticmethod
    def ask_webhook_support() -> Dict[str, Any]:
        """Ask about webhook support."""
        has_webhooks = questionary.confirm(
            "Does this connector support webhooks?",
            default=True,
        ).ask()

        if not has_webhooks:
            return {"enabled": False}

        signature_method = questionary.select(
            "Webhook signature verification method:",
            choices=[
                Choice("HMAC-SHA256", value="hmac_sha256"),
                Choice("RSA Signature", value="rsa"),
                Choice("Custom header", value="custom"),
                Choice("None (no verification)", value="none"),
            ],
        ).ask()

        return {
            "enabled": True,
            "signature_method": signature_method,
        }

    @staticmethod
    def confirm_proceed(connector_name: str, summary: Dict[str, Any]) -> bool:
        """Ask user to confirm before proceeding."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()

        table = Table(show_header=False, box=None)
        table.add_row("Connector:", connector_name)
        table.add_row("Base URL:", summary.get("base_url", "N/A"))
        table.add_row("Auth Type:", summary.get("auth_type", "N/A"))
        table.add_row("Flows:", ", ".join(summary.get("flows", [])))
        table.add_row("Payment Methods:", ", ".join(summary.get("payment_methods", [])))

        console.print("\n")
        console.print(Panel(table, title="Summary", border_style="blue"))

        return questionary.confirm(
            "Proceed with tech spec generation?",
            default=True,
        ).ask()
