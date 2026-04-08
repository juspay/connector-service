from __future__ import annotations

import uuid

from google.protobuf.json_format import ParseDict
from payments import PaymentClient

from app.config import build_connector_config, connector_for_currency
from app.models import (
    AuthorizePaymentRequest,
    AuthorizePaymentResponse,
    PaymentRecord,
    RefundPaymentRequest,
    RefundPaymentResponse,
)
from payments.generated import payment_pb2


class PaymentRouterService:
    def __init__(self, credentials: dict):
        self._credentials = credentials
        self._payments: dict[str, PaymentRecord] = {}

    def routing_rules(self) -> dict[str, str]:
        return {"USD": "stripe", "EUR": "adyen"}

    async def authorize(self, request: AuthorizePaymentRequest) -> AuthorizePaymentResponse:
        connector = connector_for_currency(request.currency)
        config = build_connector_config(connector, self._credentials)
        payment_client = PaymentClient(config)

        try:
            merchant_transaction_id = request.merchant_transaction_id or f"pay_{uuid.uuid4().hex[:16]}"
            authorize_response = await payment_client.authorize(
                self._build_authorize_request(request, merchant_transaction_id)
            )
        finally:
            await payment_client.close()

        payment_id = uuid.uuid4().hex
        record = PaymentRecord(
            payment_id=payment_id,
            merchant_transaction_id=merchant_transaction_id,
            connector=connector,
            connector_transaction_id=authorize_response.connector_transaction_id,
            currency=request.currency,
            amount_minor=request.amount_minor,
            status=payment_pb2.PaymentStatus.Name(authorize_response.status),
        )
        self._payments[payment_id] = record

        return AuthorizePaymentResponse(
            payment_id=payment_id,
            merchant_transaction_id=merchant_transaction_id,
            connector=connector,
            connector_transaction_id=authorize_response.connector_transaction_id,
            status=record.status,
        )

    async def refund(self, request: RefundPaymentRequest) -> RefundPaymentResponse:
        try:
            record = self._payments[request.payment_id]
        except KeyError as exc:
            raise KeyError(f"Unknown payment_id '{request.payment_id}'") from exc

        refund_amount_minor = request.refund_amount_minor or record.amount_minor
        config = build_connector_config(record.connector, self._credentials)
        payment_client = PaymentClient(config)

        try:
            refund_response = await payment_client.refund(
                self._build_refund_request(record, refund_amount_minor)
            )
        finally:
            await payment_client.close()

        return RefundPaymentResponse(
            payment_id=record.payment_id,
            connector=record.connector,
            connector_transaction_id=record.connector_transaction_id,
            connector_refund_id=refund_response.connector_refund_id,
            status=payment_pb2.RefundStatus.Name(refund_response.status),
        )

    def _build_authorize_request(
        self,
        request: AuthorizePaymentRequest,
        merchant_transaction_id: str,
    ) -> payment_pb2.PaymentServiceAuthorizeRequest:
        payload = {
            "merchant_transaction_id": merchant_transaction_id,
            "amount": {
                "minor_amount": request.amount_minor,
                "currency": request.currency,
            },
            "payment_method": {
                "card": {
                    "card_number": {"value": request.card.card_number},
                    "card_exp_month": {"value": request.card.card_exp_month},
                    "card_exp_year": {"value": request.card.card_exp_year},
                    "card_cvc": {"value": request.card.card_cvc},
                    "card_holder_name": {"value": request.card.card_holder_name},
                }
            },
            "capture_method": request.capture_method,
            "address": {"billing_address": {}},
            "auth_type": "NO_THREE_DS",
            "return_url": "https://example.com/return",
            # Adyen requires browser_info in its generated examples; keeping it for both connectors
            # avoids branching in the request builder.
            "browser_info": {
                "color_depth": 24,
                "screen_height": 900,
                "screen_width": 1440,
                "java_enabled": False,
                "java_script_enabled": True,
                "language": "en-US",
                "time_zone_offset_minutes": -480,
                "accept_header": "application/json",
                "user_agent": "Mozilla/5.0 (hs-paylib-routing-server)",
                "accept_language": "en-US,en;q=0.9",
                "ip_address": "1.2.3.4",
            },
        }
        return ParseDict(payload, payment_pb2.PaymentServiceAuthorizeRequest())

    def _build_refund_request(
        self,
        record: PaymentRecord,
        refund_amount_minor: int,
    ) -> payment_pb2.PaymentServiceRefundRequest:
        reason = "CUSTOMER REQUEST" if record.connector == "adyen" else "customer_request"
        payload = {
            "merchant_refund_id": f"refund_{uuid.uuid4().hex[:16]}",
            "connector_transaction_id": record.connector_transaction_id,
            "payment_amount": record.amount_minor,
            "refund_amount": {
                "minor_amount": refund_amount_minor,
                "currency": record.currency,
            },
            "reason": reason,
        }
        return ParseDict(payload, payment_pb2.PaymentServiceRefundRequest())
