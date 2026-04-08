from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.config import load_credentials
from app.models import (
    AuthorizePaymentRequest,
    AuthorizePaymentResponse,
    ErrorResponse,
    RefundPaymentRequest,
    RefundPaymentResponse,
)
from app.service import PaymentRouterService
from payments import ConnectorError, IntegrationError


app = FastAPI(title="hs-paylib routing server", version="0.1.0")
service = PaymentRouterService(load_credentials())


@app.get("/health")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/routing-rules")
async def routing_rules() -> dict[str, dict[str, str]]:
    return {"currency_to_connector": service.routing_rules()}


@app.post(
    "/payments/authorize",
    response_model=AuthorizePaymentResponse,
    responses={400: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def authorize_payment(request: AuthorizePaymentRequest) -> AuthorizePaymentResponse:
    try:
        return await service.authorize(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (ConnectorError, IntegrationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/payments/refund",
    response_model=RefundPaymentResponse,
    responses={404: {"model": ErrorResponse}, 502: {"model": ErrorResponse}},
)
async def refund_payment(request: RefundPaymentRequest) -> RefundPaymentResponse:
    try:
        return await service.refund(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ConnectorError, IntegrationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
