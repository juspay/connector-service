#!/bin/bash

# Test script for USD and EUR payments

cd "$(dirname "$0")"

# Start server
node server.js &
SERVER_PID=$!
sleep 3

echo "=== Testing USD Authorization (Stripe) ==="
USD_RESULT=$(curl -s -X POST http://localhost:3000/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "merchantTransactionId": "test_usd_'$(date +%s)'",
    "amount": 10.00,
    "currency": "USD",
    "cardNumber": "4111111111111111",
    "cardExpMonth": "12",
    "cardExpYear": "2027",
    "cardCvc": "123",
    "cardHolderName": "Test User"
  }')
echo "$USD_RESULT" | jq .

USD_TXN_ID=$(echo "$USD_RESULT" | jq -r '.connectorTransactionId // empty')

if [ ! -z "$USD_TXN_ID" ] && [ "$USD_TXN_ID" != "null" ]; then
  echo ""
  echo "=== Testing USD Refund (Stripe) ==="
  curl -s -X POST http://localhost:3000/refund \
    -H "Content-Type: application/json" \
    -d '{
      "merchantTransactionId": "test_usd_refund_'$(date +%s)'",
      "connectorTransactionId": "'$USD_TXN_ID'",
      "amount": 10.00,
      "currency": "USD"
    }' | jq .
fi

# Cleanup
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "Tests complete"
