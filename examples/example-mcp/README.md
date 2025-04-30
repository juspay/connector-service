# Example MCP Server

This is an example implementation of an MCP server that provides payment-related functionality.

## Features

- Payment authorization
- Payment sync
- Payment details retrieval

## Prerequisites

Before you begin, you need to install `uv`, a fast Python package installer and resolver:

### On Unix/macOS:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### On Windows:
```powershell
# Using PowerShell
irm https://astral.sh/uv/install.ps1 | iex
```

### Using pip:
```bash
pip install uv
```

## Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/connector-service.git
cd connector-service
```

2. Create and activate a virtual environment using uv:
```bash
cd client-sdk/example-mcp
uv venv

# Activate virtual environment
source .venv/bin/activate  # On Unix/macOS
# OR
.venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
uv pip install .
```

4. Ensure the protobuf files are generated:
The code expects the protobuf generated files to be in the following location relative to this directory:
```
../example-py/generated/
```

If the files are not present, you'll need to generate them using the protoc compiler. The main proto files are located in the `proto` directory at the root of the repository.

## Running the Server

You can run the server in two ways:

1. Using the shell script:
```bash
# Make the script executable
chmod +x payments.sh
./payments.sh
```

2. Manually:
```bash
# From the example-mcp directory
PYTHONPATH=. uv run payments.py
```

The script will automatically use the correct paths regardless of where the repository is cloned.

## Testing

You can run the test script to verify the setup:
```bash
python test_payments.py
```

Example test output:
```
=== Testing Payment Flow ===

1. Testing payment authorization...
Authorization result: {
    "status": "pending_authentication",
    "payment_id": "pay_xxx",
    "amount": 1000.0,
    "currency": "INR",
    "connector": "RAZORPAY",
    ...
}

2. Testing payment sync...
3. Testing get payment details...

=== Test Summary ===
✅ Authorization: success
✅ Sync: success
✅ Details: success
```

## Available Tools

1. `authorize_payment`: Authorize a payment with specified details
   - Required fields: amount, currency, connector
   - Optional fields: api_key, payment_method, card_details, email, reference_id

2. `sync_payment`: Sync payment status with the payment processor
   - Required fields: payment_id, connector
   - Optional fields: api_key, reference_id

3. `get_payment_details`: Get details of a specific payment
   - Required fields: payment_id

## Environment Variables

The following environment variables can be set to configure the client:

- `API_KEY`: Payment processor API key (required for production use)
- `KEY1`: Additional authentication key (required for production use)

You can set these variables in your environment or create a `.env` file:

```bash
API_KEY=<YOUR_RAZORPAY_API_KEY>
KEY1=<YOUR_RAZORPAY_KEY1>
```

Note: For security reasons, never commit your actual API keys to version control. The placeholder values in the code must be replaced with your actual keys either through environment variables or a `.env` file.

## Testing

The implementation includes a mock mode that works when gRPC dependencies are not available.

### Test Card Details
```python
card_details = {
    "card_number": "5123456789012346",
    "card_exp_month": "12",
    "card_exp_year": "2025",
    "card_cvc": "123"
}
```