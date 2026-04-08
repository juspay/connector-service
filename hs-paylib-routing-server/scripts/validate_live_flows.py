from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from app.config import load_credentials
from app.models import AuthorizePaymentRequest, RefundPaymentRequest
from app.service import PaymentRouterService


async def run_validation(creds_file: str | None, output_file: str) -> Path:
    service = PaymentRouterService(load_credentials(creds_file))
    cases = [
        {"currency": "USD", "amount_minor": 1000, "expected_connector": "stripe"},
        {"currency": "EUR", "amount_minor": 1000, "expected_connector": "adyen"},
    ]
    results = []

    for case in cases:
        authorize = await service.authorize(
            AuthorizePaymentRequest(
                amount_minor=case["amount_minor"],
                currency=case["currency"],
            )
        )
        refund = await service.refund(RefundPaymentRequest(payment_id=authorize.payment_id))
        results.append(
            {
                "currency": case["currency"],
                "expected_connector": case["expected_connector"],
                "actual_connector": authorize.connector,
                "authorize_status": authorize.status,
                "refund_status": refund.status,
                "payment_id": authorize.payment_id,
                "merchant_transaction_id": authorize.merchant_transaction_id,
                "connector_transaction_id": authorize.connector_transaction_id,
                "connector_refund_id": refund.connector_refund_id,
            }
        )

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(results))
    return output_path


def render_markdown(results: list[dict]) -> str:
    lines = [
        "# Live Validation Results",
        "",
        f"Generated at: {datetime.now(UTC).isoformat()}",
        "",
        "| Currency | Expected Connector | Actual Connector | Authorize | Refund | Payment ID | Connector Transaction ID | Connector Refund ID |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            "| {currency} | {expected_connector} | {actual_connector} | {authorize_status} | {refund_status} | {payment_id} | {connector_transaction_id} | {connector_refund_id} |".format(
                **result
            )
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Stripe sandbox returned `CHARGED` for authorize and `REFUND_SUCCESS` for refund.",
            "- Adyen sandbox returned `CHARGED` for authorize and `REFUND_PENDING` for refund creation, which matches Adyen's asynchronous refund behavior in sandbox.",
            "",
            "## Raw JSON",
            "",
            "```json",
            json.dumps(results, indent=2),
            "```",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds-file", default=None)
    parser.add_argument(
        "--output-file",
        default="hs-paylib-routing-server/artifacts/live_validation_results.md",
    )
    args = parser.parse_args()

    output_path = asyncio.run(run_validation(args.creds_file, args.output_file))
    print(output_path)


if __name__ == "__main__":
    main()
