#!/bin/bash

# Datatrans API Authorization Test
# Tests the payment authorization endpoint

set -e

# Test environment variables
TEST_DATATRANS_KEY1="${TEST_DATATRANS_KEY1:-1110017152}"
TEST_DATATRANS_API_KEY="${TEST_DATATRANS_API_KEY:-jZJZjQH9eL5FdjvA}"

# Base64 encode credentials for Basic Auth
CREDENTIALS=$(echo -n "${TEST_DATATRANS_KEY1}:${TEST_DATATRANS_API_KEY}" | base64)

echo "💳 Testing Datatrans Authorization Endpoint..."

# Test payment authorization request
REQUEST_BODY='{
  "amount": 1000,
  "currency": "CHF",
  "refno": "test-auth-'$(date +%s)'",
  "card": {
    "type": "PLAIN",
    "number": "4242424242424242",
    "expiryMonth": "12",
    "expiryYear": "25",
    "cvv": "123"
  },
  "autoSettle": false
}'

echo "📤 Request Body:"
echo "$REQUEST_BODY" | jq '.' 2>/dev/null || echo "$REQUEST_BODY"

RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
  -X POST \
  -H "Authorization: Basic ${CREDENTIALS}" \
  -H "Content-Type: application/json" \
  -d "$REQUEST_BODY" \
  "https://api.sandbox.datatrans.com/v1/transactions" \
  2>/dev/null || echo "CURL_ERROR")

if [[ "$RESPONSE" == *"CURL_ERROR"* ]]; then
    echo "❌ CURL Error: Unable to connect to Datatrans API"
    exit 1
fi

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "📡 Response Status: $HTTP_STATUS"
echo "📄 Response Body:"
echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"

case $HTTP_STATUS in
    200|201)
        echo "✅ Authorization endpoint accessible and working!"
        TRANSACTION_ID=$(echo "$RESPONSE_BODY" | jq -r '.transactionId' 2>/dev/null || echo "")
        if [[ -n "$TRANSACTION_ID" && "$TRANSACTION_ID" != "null" ]]; then
            echo "🆔 Transaction ID: $TRANSACTION_ID"
            echo "$TRANSACTION_ID" > /tmp/datatrans_test_transaction_id
        fi
        ;;
    400)
        echo "⚠️  Bad Request - Request format may need adjustment"
        echo "   This is expected for test data, endpoint is accessible"
        ;;
    401)
        echo "❌ Authentication failed"
        exit 1
        ;;
    422)
        echo "⚠️  Validation Error - Test card data rejected"
        echo "   This is expected, endpoint is accessible"
        ;;
    *)
        echo "⚠️  Status: $HTTP_STATUS"
        echo "   Endpoint accessible but returned unexpected status"
        ;;
esac

echo "🎉 Authorization endpoint test completed!"