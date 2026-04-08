from __future__ import annotations

import json
import os
from pathlib import Path

from payments import ConnectorConfig, ConnectorSpecificConfig, Environment, SdkOptions
from payments.generated import payment_methods_pb2, payment_pb2


DEFAULT_CREDS_CANDIDATES = [
    Path(os.environ.get("HS_ROUTER_CREDS_FILE", "")) if os.environ.get("HS_ROUTER_CREDS_FILE") else None,
    Path(__file__).resolve().parents[2] / "creds.json",
    Path("/Users/amitsingh.tanwar/Documents/connector-service/connector-service-02/connector-service/.github/test/creds.json"),
]

CONNECTOR_BY_CURRENCY = {
    "USD": "stripe",
    "EUR": "adyen",
}


def _secret(value: str) -> payment_methods_pb2.SecretString:
    return payment_methods_pb2.SecretString(value=value)


def resolve_creds_file(explicit_path: str | None = None) -> Path:
    candidates = [Path(explicit_path)] if explicit_path else []
    candidates.extend(candidate for candidate in DEFAULT_CREDS_CANDIDATES if candidate is not None)

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"Could not locate creds.json. Searched: {searched}")


def load_credentials(explicit_path: str | None = None) -> dict:
    return json.loads(resolve_creds_file(explicit_path).read_text())


def connector_for_currency(currency: str) -> str:
    normalized = currency.upper()
    try:
        return CONNECTOR_BY_CURRENCY[normalized]
    except KeyError as exc:
        supported = ", ".join(sorted(CONNECTOR_BY_CURRENCY))
        raise ValueError(f"Unsupported currency '{currency}'. Supported currencies: {supported}") from exc


def build_connector_config(connector_name: str, credentials: dict) -> ConnectorConfig:
    connector_key = connector_name.lower()

    if connector_key == "stripe":
        connector_specific = ConnectorSpecificConfig(
            stripe=payment_pb2.StripeConfig(
                api_key=_secret(credentials["stripe"]["api_key"]["value"]),
            )
        )
    elif connector_key == "adyen":
        connector_specific = ConnectorSpecificConfig(
            adyen=payment_pb2.AdyenConfig(
                api_key=_secret(credentials["adyen"]["api_key"]["value"]),
                merchant_account=_secret(credentials["adyen"]["merchant_account"]["value"]),
                review_key=_secret(credentials["adyen"]["review_key"]["value"]),
            )
        )
    else:
        raise ValueError(f"Unsupported connector '{connector_name}'")

    return ConnectorConfig(
        connector_config=connector_specific,
        options=SdkOptions(environment=Environment.SANDBOX),
    )
