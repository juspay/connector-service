#!/usr/bin/env python3
"""
gRPC Generator - Creates gRPC cURL commands for payment operations
Reads environment variables and JSON templates to generate cURL commands
"""

import os
import json
import time
import sys
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Try to import dotenv, fallback to manual env loading if not available
try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False
    print("Warning: python-dotenv not installed. Using environment variables directly.")
    print("Install with: pip install python-dotenv")


class GrpcGenerator:
    def __init__(self, env_file: str = ".env.grpc"):
        """Initialize the gRPC generator with environment configuration"""
        # Minimal verification - just check if env file exists
        if not Path(env_file).exists():
            raise FileNotFoundError(f"Environment configuration file not found: {env_file}")

        # Load environment variables
        if HAS_DOTENV:
            load_dotenv(env_file)
        elif os.path.exists(env_file):
            # Manual loading of .env file if dotenv is not available
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip().strip('"\'')
            print(f"Loaded configuration from: {env_file}")

        # Load configuration from environment
        self.connector_name = os.getenv("CONNECTOR_NAME", "tsys")
        self.auth_type = os.getenv("CONNECTOR_AUTH_TYPE", "signature-key")
        self.api_key = os.getenv("CONNECTOR_API_KEY", "")
        self.api_secret = os.getenv("CONNECTOR_API_SECRET", "")
        self.key1 = os.getenv("CONNECTOR_KEY1", "")
        self.key2 = os.getenv("CONNECTOR_KEY2", "")
        self.merchant_id = os.getenv("CONNECTOR_MERCHANT_ID", "merchant_100")
        self.server_url = os.getenv("GRPC_SERVER_URL", "localhost:8000")

        # Load card details from environment
        self.card_number = os.getenv("CARD_NUMBER", "4242424242424242")
        self.card_exp_month = os.getenv("CARD_EXP_MONTH", "10")
        self.card_exp_year = os.getenv("CARD_EXP_YEAR", "30")
        self.card_cvc = os.getenv("CARD_CVC", "123")
        self.card_holder_name = os.getenv("CARD_HOLDER_NAME", "Test User")
        self.card_network = os.getenv("CARD_NETWORK", "VISA")

        # Load request templates
        self.requests_dir = Path("grpc_requests")
        self.configs_dir = Path("grpc_configs")

        # Ensure directories exist
        self.requests_dir.mkdir(exist_ok=True)
        self.configs_dir.mkdir(exist_ok=True)

    def build_headers(self) -> List[str]:
        """Build gRPC headers based on authentication type"""
        headers = [
            f'-H "x-connector: {self.connector_name}"',
            f'-H "x-auth: {self.auth_type}"',
            f'-H "x-merchant-id: {self.merchant_id}"'
        ]

        if self.api_key:
            headers.append(f'-H "x-api-key: {self.api_key}"')
        if self.api_secret:
            headers.append(f'-H "x-api-secret: {self.api_secret}"')
        if self.key1:
            headers.append(f'-H "x-key1: {self.key1}"')
        if self.key2:
            headers.append(f'-H "x-key2: {self.key2}"')

        # Add reference_id header for powertranz connector
        if self.connector_name.lower() == "powertranz":
            headers.append(f'-H "reference_id: {self.key1}"')

        return headers

    def replace_placeholders(self, template: Dict[str, Any],
                           ref_id: str,
                           transaction_id: str = None,
                           refund_id: str = None,
                           capture_method: str = "MANUAL") -> str:
        """Replace template placeholders with actual values"""
        # Connector-specific metadata
        if self.connector_name.lower() == "tsys":
            tenant_id = "1234"
            platform_url = "185.149.63.6:19585"
        elif self.connector_name.lower() == "powertranz":
            tenant_id = "1234"
            platform_url = "185.149.63.6:19585"
        else:
            tenant_id = ""
            platform_url = ""

        # Convert to JSON string for simple string replacements
        template_str = json.dumps(template, indent=2)

        # Replace string placeholders
        template_str = template_str.replace("{{TENANT_ID}}", tenant_id)
        template_str = template_str.replace("{{PLATFORM_URL}}", platform_url)
        template_str = template_str.replace("{{REF_ID}}", ref_id)
        template_str = template_str.replace("{{TRANSACTION_ID}}", transaction_id or "")
        template_str = template_str.replace("{{REFUND_ID}}", refund_id or "")
        template_str = template_str.replace("{{CAPTURE_METHOD}}", capture_method)

        # Replace card detail placeholders
        template_str = template_str.replace("{{CARD_NUMBER}}", self.card_number)
        template_str = template_str.replace("{{CARD_EXP_MONTH}}", self.card_exp_month)
        template_str = template_str.replace("{{CARD_EXP_YEAR}}", self.card_exp_year)
        template_str = template_str.replace("{{CARD_CVC}}", self.card_cvc)
        template_str = template_str.replace("{{CARD_HOLDER_NAME}}", self.card_holder_name)
        template_str = template_str.replace("{{CARD_NETWORK}}", self.card_network)

        return template_str

    def load_request_template(self, operation: str) -> Dict[str, Any]:
        """Load JSON template for a specific operation"""
        template_file = self.requests_dir / f"{operation}.json"

        if not template_file.exists():
            raise FileNotFoundError(f"Template not found: {template_file}")

        with open(template_file, 'r') as f:
            return json.load(f)

    def generate_grpc_curl(self, operation: str,
                          ref_id: str,
                          transaction_id: str = None,
                          refund_id: str = None,
                          capture_method: str = "MANUAL") -> str:
        """
        Generate gRPC cURL command for a specific operation

        Args:
            operation: 'auth', 'capture', 'void', 'refund', 'sync'
            ref_id: Reference ID for the request
            transaction_id: Transaction ID for dependent operations
            capture_method: 'MANUAL' or 'AUTOMATIC'

        Returns:
            Complete gRPC cURL command as a string
        """
        # Service mapping
        service_methods = {
            "auth": ("ucs.v2.PaymentService", "Authorize"),
            "capture": ("ucs.v2.PaymentService", "Capture"),
            "void": ("ucs.v2.PaymentService", "Void"),
            "refund": ("ucs.v2.PaymentService", "Refund"),
            "sync": ("ucs.v2.PaymentService", "Get"),
            "rsync": ("ucs.v2.RefundService", "Get")
        }

        if operation not in service_methods:
            raise ValueError(f"Unknown operation: {operation}")

        service, method = service_methods[operation]

        # Load and prepare request JSON
        template = self.load_request_template(operation)
        request_json = self.replace_placeholders(
            template, ref_id, transaction_id, refund_id, capture_method
        )

        # Build headers
        headers = self.build_headers()

        # Construct the gRPC cURL command
        curl_parts = [
            "grpcurl",
            "-plaintext",
            *headers,
            "-d",
            f"'{request_json}'",
            f"{self.server_url} {service}/{method}"
        ]

        return " ".join(curl_parts)

    def save_configuration(self, filename: str = "current_config.json"):
        """Save current configuration to JSON file"""
        config = {
            "connector_name": self.connector_name,
            "auth_type": self.auth_type,
            "api_key": self.api_key,
            "api_secret": self.api_secret,
            "key1": self.key1,
            "key2": self.key2,
            "merchant_id": self.merchant_id,
            "server_url": self.server_url,
            "card_details": {
                "card_number": self.card_number,
                "card_exp_month": self.card_exp_month,
                "card_exp_year": self.card_exp_year,
                "card_cvc": self.card_cvc,
                "card_holder_name": self.card_holder_name,
                "card_network": self.card_network
            }
        }

        config_path = self.configs_dir / filename
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"Configuration saved to: {config_path}")
        return config_path


if __name__ == "__main__":
    # Example usage
    generator = GrpcGenerator()

    # Save current configuration
    generator.save_configuration()

    # Generate example cURL commands
    print("\n=== Generated gRPC Commands ===")

    operations = ["auth", "capture", "void", "refund", "sync"]
    for op in operations:
        try:
            curl_cmd = generator.generate_grpc_curl(
                op,
                f"test_{op}_{int(time.time())}",
                transaction_id="txn_12345" if op != "auth" else None,
                capture_method="MANUAL"
            )
            print(f"\n{op.upper()}:")
            print(curl_cmd)
        except Exception as e:
            print(f"Error generating {op}: {e}")