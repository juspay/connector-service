#!/bin/bash

# Datatrans API Authentication Test
# Tests basic connectivity and authentication with Datatrans API

set -e

# Test environment variables
TEST_DATATRANS_KEY1="${TEST_DATATRANS_KEY1:-1110017152}"
TEST_DATATRANS_API_KEY="${TEST_DATATRANS_API_KEY:-jZJZjQH9eL5FdjvA}"

# Base64 encode credentials for Basic Auth
CREDENTIALS=$(echo -n "${TEST_DATATRANS_KEY1}:${TEST_DATATRANS_API_KEY}" | base64)

echo "🔐 Testing Datatrans API Authentication..."
echo "Merchant ID: ${TEST_DATATRANS_KEY1}"
echo "API Key: ${TEST_DATATRANS_API_KEY:0:8}..."

# Test authentication with a simple transaction status check
# Using a dummy transaction ID to test auth (will return 404 but with proper auth)
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
  -X GET \
  -H "Authorization: Basic ${CREDENTIALS}" \
  -H "Content-Type: application/json" \
  "https://api.sandbox.datatrans.com/v1/transactions/dummy-test-id" \
  2>/dev/null || echo "CURL_ERROR")

if [[ "$RESPONSE" == *"CURL_ERROR"* ]]; then
    echo "❌ CURL Error: Unable to connect to Datatrans API"
    echo "   Check internet connectivity and API endpoint"
    exit 1
fi

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "📡 Response Status: $HTTP_STATUS"
echo "📄 Response Body: $RESPONSE_BODY"

case $HTTP_STATUS in
    200|201)
        echo "✅ Authentication successful!"
        ;;
    401)
        echo "❌ Authentication failed - Invalid credentials"
        echo "   Check TEST_DATATRANS_KEY1 and TEST_DATATRANS_API_KEY"
        exit 1
        ;;
    404)
        echo "✅ Authentication successful (404 expected for dummy transaction)"
        ;;
    403)
        echo "❌ Forbidden - Check API permissions"
        exit 1
        ;;
    *)
        echo "⚠️  Unexpected status code: $HTTP_STATUS"
        echo "   This may indicate API issues or network problems"
        ;;
esac

echo "🎉 Authentication test completed successfully!"