# Payment SDK Script Demo

TypeScript CLI demo for processing payments using `hs-playlib`. This example demonstrates two payment flows: `authorize` and `accessToken+authorize` across multiple connectors.

## Supported Flows

| Flow | Description | Connectors |
|------|-------------|------------|
| `authorize` | Direct authorization request | Stripe, Worldpay |
| `accessToken+authorize` | First obtains access token, then performs authorization | PayPal |

## Prerequisites

- Node.js installed
- Install dependencies:
  ```bash
  npm install
  ```

## Configuration

**Before running the script, you must update your credentials in `src/config/index.ts`:**

```typescript
export const PAYPAL_CREDS = {
    client_id: "your_paypal_client_id",
    client_secret: "your_paypal_client_secret",
};

export const STRIPE_CREDS = {
    api_key: "your_stripe_api_key"
}

export const WORLDPAY_CREDS = {
    username: "your_worldpay_username",
    password: "your_worldpay_password",
    entity_id: "your_worldpay_entity_id"
}
```

### Credentials Required per Connector

| Connector | Required Credentials |
|-----------|---------------------|
| PayPal | `client_id`, `client_secret` |
| Stripe | `api_key` |
| Worldpay | `username`, `password`, `entity_id` |

## Usage

### Commands to Run

**Option 1: Direct with ts-node**
```bash
npx ts-node src/index.ts <connector>
```

**Option 2: Using npm script (builds and runs)**
```bash
npm run start -- <connector>
```

**Option 3: Manual build then run**
```bash
npm run build
node dist/index.js <connector>
```

### Arguments

- `<connector>` (required): The payment connector to use. Supported values: `paypal`, `stripe`, `worldpay`

### Examples

```bash
# Run with PayPal (uses accessToken+authorize flow)
npx ts-node src/index.ts paypal
npm run start -- paypal

# Run with Stripe (uses authorize flow)
npx ts-node src/index.ts stripe
npm run start -- stripe

# Run with Worldpay (uses authorize flow)
npx ts-node src/index.ts worldpay
npm run start -- worldpay
```

## What the Script Does

- Performs a **$10.00 USD** test authorization
- Uses test card: `4111111111111111` (Visa)
- Expiration: `12/2050`, CVC: `123`
- Cardholder: `Test User`
- Outputs:
  - Transaction ID on successful payment (`CHARGED` status)
  - Error details on failure (`FAILURE` status or exceptions)