# hs-paylib Python Payment Server

A FastAPI server demonstrating payment processing with the `hs-paylib` Python SDK, routing USD payments through Stripe and EUR payments through Adyen.

## Features

- **Currency-based routing:** USD → Stripe, EUR → Adyen
- **Payment authorization** with automatic capture
- **Refund processing**
- **Health check endpoint**
- **Test scripts** for validation

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and configure your credentials:

```bash
cp .env.example .env
```

Edit `.env` with your API keys:
- `STRIPE_API_KEY` - Your Stripe secret key
- `ADYEN_API_KEY` - Your Adyen API key
- `ADYEN_MERCHANT_ACCOUNT` - Your Adyen merchant account

## Usage

### Start the server

```bash
python main.py
# or
uvicorn main:app --reload --port 8000
```

Server runs on port 8000 by default (configurable via `PORT` env var).

### API Endpoints

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Authorize Payment
```bash
curl -X POST http://localhost:8000/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "merchant_transaction_id": "txn_001",
    "amount": 10.00,
    "currency": "USD",
    "card_number": "4111111111111111",
    "card_exp_month": "12",
    "card_exp_year": "2027",
    "card_cvc": "123",
    "card_holder_name": "Test User"
  }'
```

Routes:
- **USD** → Stripe
- **EUR** → Adyen

#### Refund Payment
```bash
curl -X POST http://localhost:8000/refund \
  -H "Content-Type: application/json" \
  -d '{
    "merchant_transaction_id": "txn_001",
    "connector_transaction_id": "pi_xxx",
    "amount": 10.00,
    "currency": "USD"
  }'
```

### Testing

Run the test script:

```bash
python test.py
```

Or test manually:

```bash
./test-payment.sh
```

## Project Structure

```
hs-paylib-python/
├── main.py            # FastAPI server
├── test.py           # Test suite
├── test-payment.sh   # Quick test script
├── requirements.txt  # Python dependencies
├── .env             # Configuration (gitignored)
├── .env.example     # Configuration template
├── .gitignore       # Git ignore file
├── README.md        # This file
└── FRICTION_LOG.md  # Integration friction log
```

## Connector Configuration

### Stripe (USD)
```python
stripe_config = types.ConnectorConfig({
    "connectorConfig": {
        "stripe": {
            "apiKey": {"value": os.getenv("STRIPE_API_KEY")}
        }
    }
})
```

### Adyen (EUR)
```python
adyen_config = types.ConnectorConfig({
    "connectorConfig": {
        "adyen": {
            "apiKey": {"value": os.getenv("ADYEN_API_KEY")},
            "merchantAccount": {"value": os.getenv("ADYEN_MERCHANT_ACCOUNT")}
        }
    }
})
```

## Notes

- Adyen requires `browser_info` for 3D Secure compliance
- Field naming uses snake_case for FFI compatibility
- Status codes are numeric (see FRICTION_LOG.md for mapping)

## Documentation

See [FRICTION_LOG.md](./FRICTION_LOG.md) for detailed integration experience, friction points, and recommendations.
