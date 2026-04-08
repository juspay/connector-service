from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CardInput(BaseModel):
    card_number: str = Field(default="4111111111111111")
    card_exp_month: str = Field(default="03")
    card_exp_year: str = Field(default="2030")
    card_cvc: str = Field(default="737")
    card_holder_name: str = Field(default="John Doe")


class AuthorizePaymentRequest(BaseModel):
    amount_minor: int = Field(gt=0)
    currency: Literal["USD", "EUR"]
    merchant_transaction_id: str | None = None
    capture_method: Literal["AUTOMATIC", "MANUAL"] = "AUTOMATIC"
    card: CardInput = Field(default_factory=CardInput)


class RefundPaymentRequest(BaseModel):
    payment_id: str
    refund_amount_minor: int | None = Field(default=None, gt=0)


class PaymentRecord(BaseModel):
    payment_id: str
    merchant_transaction_id: str
    connector: Literal["stripe", "adyen"]
    connector_transaction_id: str
    currency: Literal["USD", "EUR"]
    amount_minor: int
    status: str


class AuthorizePaymentResponse(BaseModel):
    payment_id: str
    merchant_transaction_id: str
    connector: str
    connector_transaction_id: str
    status: str


class RefundPaymentResponse(BaseModel):
    payment_id: str
    connector: str
    connector_transaction_id: str
    connector_refund_id: str
    status: str


class ErrorResponse(BaseModel):
    detail: str
