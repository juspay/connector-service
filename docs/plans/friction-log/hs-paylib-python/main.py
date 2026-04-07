"""
hs-paylib Python Payment Server
Routes USD payments to Stripe, EUR payments to Adyen
"""

import os
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from payments import PaymentClient, types

app = FastAPI(title="hs-paylib Payment Server")

# Payment client instances (initialized lazily)
_stripe_client: Optional[PaymentClient] = None
_adyen_client: Optional[PaymentClient] = None


class AuthorizeRequest(BaseModel):
    merchant_transaction_id: str
    amount: float
    currency: str = Field(pattern="^(USD|EUR)$")
    card_number: str
    card_exp_month: str = "12"
    card_exp_year: str = "2027"
    card_cvc: str = "123"
    card_holder_name: str = "Test User"


class RefundRequest(BaseModel):
    merchant_transaction_id: str
    connector_transaction_id: str
    amount: float
    currency: str = Field(pattern="^(USD|EUR)$")


def get_stripe_client() -> PaymentClient:
    """Initialize Stripe client for USD payments"""
    global _stripe_client
    if _stripe_client is None:
        stripe_config = types.ConnectorConfig({
            "connectorConfig": {
                "stripe": {
                    "apiKey": {"value": os.getenv("STRIPE_API_KEY")}
                }
            }
        })
        request_config = types.RequestConfig({
            "http": {
                "totalTimeoutMs": 30000,
                "connectTimeoutMs": 10000,
            }
        })
        _stripe_client = PaymentClient(stripe_config, request_config)
        print("Stripe client initialized")
    return _stripe_client


def get_adyen_client() -> PaymentClient:
    """Initialize Adyen client for EUR payments"""
    global _adyen_client
    if _adyen_client is None:
        adyen_config = types.ConnectorConfig({
            "connectorConfig": {
                "adyen": {
                    "apiKey": {"value": os.getenv("ADYEN_API_KEY")},
                    "merchantAccount": {"value": os.getenv("ADYEN_MERCHANT_ACCOUNT")}
                }
            }
        })
        request_config = types.RequestConfig({
            "http": {
                "totalTimeoutMs": 30000,
                "connectTimeoutMs": 10000,
            }
        })
        _adyen_client = PaymentClient(adyen_config, request_config)
        print("Adyen client initialized")
    return _adyen_client


def get_client_for_currency(currency: str):
    """Get appropriate client and connector based on currency"""
    currency_upper = currency.upper()
    if currency_upper == "USD":
        return get_stripe_client(), types.Connector.STRIPE
    elif currency_upper == "EUR":
        return get_adyen_client(), types.Connector.ADYEN
    else:
        raise ValueError(f"Unsupported currency: {currency}")


def map_status(status: int) -> str:
    """Map numeric status to human-readable string"""
    status_map = {
        0: "PENDING",
        1: "PROCESSING",
        2: "SUCCESS",
        3: "FAILED",
        4: "CANCELLED",
        5: "AUTHORIZED",
        6: "CAPTURED",
        7: "REFUNDED",
        8: "CHARGED",
    }
    return status_map.get(status, f"UNKNOWN({status})")


def get_currency_enum(currency: str):
    """Get currency enum value"""
    currency_upper = currency.upper()
    if currency_upper == "USD":
        return types.Currency.USD
    elif currency_upper == "EUR":
        return types.Currency.EUR
    else:
        raise ValueError(f"Unsupported currency: {currency}")


@app.post("/authorize")
async def authorize_payment(request: AuthorizeRequest):
    """Authorize a payment - routes USD to Stripe, EUR to Adyen"""
    try:
        client, connector = get_client_for_currency(request.currency)
        currency_upper = request.currency.upper()

        # Build authorize request
        authorize_request = {
            "merchantTransactionId": request.merchant_transaction_id,
            "amount": {
                "minorAmount": int(request.amount * 100),  # Convert to cents
                "currency": get_currency_enum(currency_upper),
            },
            "captureMethod": types.CaptureMethod.AUTOMATIC,
            "paymentMethod": {
                "card": {
                    "cardNumber": {"value": request.card_number},
                    "cardExpMonth": {"value": request.card_exp_month},
                    "cardExpYear": {"value": request.card_exp_year},
                    "cardCvc": {"value": request.card_cvc},
                    "cardHolderName": {"value": request.card_holder_name},
                }
            },
            "address": {"billingAddress": {}},
            "authType": types.AuthenticationType.NO_THREE_DS,
            "returnUrl": "https://example.com/return",
            "orderDetails": [],
        }

        # Adyen requires browser_info for 3D Secure compliance
        if currency_upper == "EUR":
            authorize_request["browserInfo"] = {
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "accept_header": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "language": "en-US",
                "color_depth": 24,
                "screen_height": 1080,
                "screen_width": 1920,
                "time_zone": -480,
                "java_enabled": False,
                "java_script_enabled": True,
            }

        print(f"Processing authorization for {currency_upper} via {connector.name}...")
        response = client.authorize(authorize_request)

        status_text = map_status(response.status)
        print(f"Authorization successful: status={response.status}, txn={response.connectorTransactionId}")

        return {
            "success": True,
            "status": response.status,
            "statusText": status_text,
            "connectorTransactionId": response.connectorTransactionId,
            "merchantTransactionId": response.merchantTransactionId,
            "currency": currency_upper,
            "connector": connector.name.lower(),
        }

    except Exception as e:
        print(f"Authorization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/refund")
async def refund_payment(request: RefundRequest):
    """Refund a payment - routes based on original currency"""
    try:
        client, connector = get_client_for_currency(request.currency)
        currency_upper = request.currency.upper()

        # Build refund request
        refund_request = {
            "merchantTransactionId": f"{request.merchant_transaction_id}_refund_{int(datetime.now().timestamp())}",
            "refundAmount": {
                "minorAmount": int(request.amount * 100),
                "currency": get_currency_enum(currency_upper),
            },
            "connectorTransactionId": request.connector_transaction_id,
            "reason": "Customer requested refund",
        }

        print(f"Processing refund for {currency_upper} via {connector.name}...")
        response = client.refund(refund_request)

        status_text = map_status(response.status)
        print(f"Refund successful: status={response.status}, refund_txn={response.connectorRefundTransactionId}")

        return {
            "success": True,
            "status": response.status,
            "statusText": status_text,
            "connectorRefundTransactionId": response.connectorRefundTransactionId,
            "merchantTransactionId": response.merchantTransactionId,
            "currency": currency_upper,
            "connector": connector.name.lower(),
        }

    except Exception as e:
        print(f"Refund error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "stripeConfigured": bool(os.getenv("STRIPE_API_KEY")),
        "adyenConfigured": bool(os.getenv("ADYEN_API_KEY") and os.getenv("ADYEN_MERCHANT_ACCOUNT")),
    }


@app.get("/")
async def root():
    """API info"""
    return {
        "name": "hs-paylib Payment Server (Python)",
        "description": "Payment routing: USD -> Stripe, EUR -> Adyen",
        "endpoints": {
            "POST /authorize": "Authorize a payment",
            "POST /refund": "Refund a payment",
            "GET /health": "Health check",
        },
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    print(f"""
╔════════════════════════════════════════════════════════╗
║          hs-paylib Payment Server (Python)             ║
╠════════════════════════════════════════════════════════╣
║  Server running on port {port}                        ║
║                                                        ║
║  Routing:                                              ║
║    USD → Stripe                                        ║
║    EUR → Adyen                                         ║
║                                                        ║
║  Endpoints:                                            ║
║    POST /authorize - Process payments                  ║
║    POST /refund    - Process refunds                   ║
║    GET  /health    - Health check                      ║
╚════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=port)
