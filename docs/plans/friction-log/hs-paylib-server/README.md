# hs-paylib Payment Server

A Node.js server demonstrating payment processing with the `hs-paylib` SDK, routing USD payments through Stripe and EUR payments through Adyen.

## Features

- **Currency-based routing:** USD → Stripe, EUR → Adyen
- **Payment authorization** with automatic capture
- **Refund processing**
- **Health check endpoint**
- **Test scripts** for validation

## Installation

```bash
npm install
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
npm start
# or
node server.js
```

Server runs on port 3000 by default (configurable via `PORT` env var).

### API Endpoints

#### Health Check
```bash
GET http://localhost:3000/health
```

#### Authorize Payment
```bash
POST http://localhost:3000/authorize
Content-Type: application/json

{
  "merchantTransactionId": "txn_001",
  "amount": 10.00,
  "currency": "USD",
  "cardNumber": "4111111111111111",
  "cardExpMonth": "12",
  "cardExpYear": "2027",
  "cardCvc": "123",
  "cardHolderName": "Test User"
}
```

Routes:
- **USD** → Stripe
- **EUR** → Adyen

#### Refund Payment
```bash
POST http://localhost:3000/refund
Content-Type: application/json

{
  "merchantTransactionId": "txn_001",
  "connectorTransactionId": "pi_xxx",
  "amount": 10.00,
  "currency": "USD"
}
```

### Testing

Run the test suite:

```bash
npm test
# or
node test.js
```

Or use the shell script:

```bash
./test-payment.sh
```

## Project Structure

```
hs-paylib-server/
├── server.js           # Main server file
├── test.js            # Test suite
├── test-payment.sh    # Quick test script
├── package.json       # Dependencies
├── .env              # Configuration (gitignored)
├── .env.example      # Configuration template
├── creds.json        # API credentials (downloaded)
├── README.md         # This file
└── FRICTION_LOG.md   # Integration friction log
```

## Connector Configuration

### Stripe (USD)
```javascript
{
  connectorConfig: {
    stripe: {
      apiKey: { value: process.env.STRIPE_API_KEY }
    }
  }
}
```

### Adyen (EUR)
```javascript
{
  connectorConfig: {
    adyen: {
      apiKey: { value: process.env.ADYEN_API_KEY },
      merchantAccount: { value: process.env.ADYEN_MERCHANT_ACCOUNT }
    }
  }
}
```

## Notes

- Adyen requires `browserInfo` for 3D Secure compliance
- Field naming uses snake_case for FFI compatibility
- Status codes are numeric (see FRICTION_LOG.md for mapping)

## Documentation

See [FRICTION_LOG.md](./FRICTION_LOG.md) for detailed integration experience, friction points, and recommendations.
