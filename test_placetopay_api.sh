#!/bin/bash

# PlaceToPay API Test Script
# This script tests the PlaceToPay API directly to validate authentication and basic functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}PlaceToPay API Direct Test${NC}"
echo "=================================="

# Check if environment variables are set
if [ -z "$TEST_PLACETOPAY_API_KEY" ] || [ -z "$TEST_PLACETOPAY_KEY1" ]; then
    echo -e "${RED}Error: Environment variables not set${NC}"
    echo "Please set:"
    echo "  export TEST_PLACETOPAY_API_KEY='your_api_key'"
    echo "  export TEST_PLACETOPAY_KEY1='your_secret_key'"
    exit 1
fi

# PlaceToPay API configuration
BASE_URL="https://test.placetopay.com/rest/gateway"
LOGIN="$TEST_PLACETOPAY_API_KEY"
TRAN_KEY="$TEST_PLACETOPAY_KEY1"

# Generate authentication
NONCE=$(openssl rand -base64 16)
SEED=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
HASH_INPUT="${NONCE}${SEED}${TRAN_KEY}"
TRAN_KEY_HASH=$(echo -n "$HASH_INPUT" | openssl dgst -sha256 -binary | base64)

echo -e "${YELLOW}Authentication Details:${NC}"
echo "Login: $LOGIN"
echo "Seed: $SEED"
echo "Nonce: $NONCE"
echo "Hash: $TRAN_KEY_HASH"
echo ""

# Create payment request
PAYMENT_REQUEST=$(cat <<EOF
{
  "auth": {
    "login": "$LOGIN",
    "tranKey": "$TRAN_KEY_HASH",
    "nonce": "$NONCE",
    "seed": "$SEED"
  },
  "payment": {
    "reference": "test_$(date +%s)",
    "description": "Test payment from CURL",
    "amount": {
      "currency": "USD",
      "total": 1000
    }
  },
  "instrument": {
    "card": {
      "number": "4111111111111111",
      "expiration": "10/30",
      "cvv": "123"
    }
  },
  "ipAddress": "127.0.0.1",
  "userAgent": "curl/test"
}
EOF
)

echo -e "${YELLOW}Testing PlaceToPay Payment API...${NC}"
echo "URL: $BASE_URL/process"
echo ""

# Make the API call
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "$PAYMENT_REQUEST" \
  "$BASE_URL/process")

# Extract HTTP status and response body
HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

echo -e "${YELLOW}Response:${NC}"
echo "HTTP Status: $HTTP_STATUS"
echo "Response Body:"
echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
echo ""

# Check if the request was successful
if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 201 ]; then
    echo -e "${GREEN}✓ API call successful!${NC}"
    
    # Extract status from response
    STATUS=$(echo "$RESPONSE_BODY" | jq -r '.status.status' 2>/dev/null || echo "unknown")
    echo "Payment Status: $STATUS"
    
    if [ "$STATUS" = "APPROVED" ] || [ "$STATUS" = "OK" ]; then
        echo -e "${GREEN}✓ Payment approved!${NC}"
    elif [ "$STATUS" = "PENDING" ]; then
        echo -e "${YELLOW}⚠ Payment pending${NC}"
    else
        echo -e "${RED}✗ Payment failed or rejected${NC}"
    fi
else
    echo -e "${RED}✗ API call failed with HTTP status: $HTTP_STATUS${NC}"
    echo "This indicates an authentication or API configuration issue."
fi

echo ""
echo -e "${YELLOW}Test completed.${NC}"