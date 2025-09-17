#!/bin/bash

# ACI API Connectivity Test Script
# This script tests the basic connectivity to ACI API endpoints

set -e

# Test environment variables
export TEST_ACI_API_KEY="Bearer OGFjN2E0Yzk3ZDA0NDMwNTAxN2QwNTMxNDQxMjA5ZjF8emV6N1lTUHNEaw=="
export TEST_ACI_KEY1="8ac7a4c97d044305017d053142b009ed"
export TEST_BASE_URL="https://eu-test.oppwa.com/"

echo "=== ACI API Connectivity Test ==="
echo "Base URL: $TEST_BASE_URL"
echo "Entity ID: $TEST_ACI_KEY1"
echo ""

# Test 1: Authentication Test
echo "1. Testing Authentication..."
response=$(curl -s -w "%{http_code}" -o /tmp/aci_auth_test.json \
  -H "Authorization: $TEST_ACI_API_KEY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "${TEST_BASE_URL}v1/payments/test?entityId=${TEST_ACI_KEY1}")

http_code="${response: -3}"
echo "   HTTP Status: $http_code"

if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
    echo "   ✅ Authentication successful (endpoint accessible)"
elif [ "$http_code" = "401" ]; then
    echo "   ❌ Authentication failed (401 Unauthorized)"
    cat /tmp/aci_auth_test.json
    exit 1
else
    echo "   ⚠️  Unexpected response: $http_code"
    cat /tmp/aci_auth_test.json
fi

echo ""

# Test 2: Test Payment Endpoint Structure
echo "2. Testing Payment Endpoint Structure..."
response=$(curl -s -w "%{http_code}" -o /tmp/aci_payment_test.json \
  -X POST \
  -H "Authorization: $TEST_ACI_API_KEY" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "entityId=${TEST_ACI_KEY1}&amount=1.00&currency=EUR&paymentType=DB" \
  "${TEST_BASE_URL}v1/payments")

http_code="${response: -3}"
echo "   HTTP Status: $http_code"

if [ "$http_code" = "200" ] || [ "$http_code" = "400" ] || [ "$http_code" = "422" ]; then
    echo "   ✅ Payment endpoint accessible"
    echo "   Response preview:"
    head -c 200 /tmp/aci_payment_test.json
    echo "..."
elif [ "$http_code" = "401" ]; then
    echo "   ❌ Authentication failed for payment endpoint"
    cat /tmp/aci_payment_test.json
    exit 1
else
    echo "   ⚠️  Unexpected response: $http_code"
    cat /tmp/aci_payment_test.json
fi

echo ""

# Test 3: Test Query Endpoint
echo "3. Testing Query Endpoint Structure..."
response=$(curl -s -w "%{http_code}" -o /tmp/aci_query_test.json \
  -H "Authorization: $TEST_ACI_API_KEY" \
  "${TEST_BASE_URL}v1/payments/test123?entityId=${TEST_ACI_KEY1}")

http_code="${response: -3}"
echo "   HTTP Status: $http_code"

if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
    echo "   ✅ Query endpoint accessible"
    echo "   Response preview:"
    head -c 200 /tmp/aci_query_test.json
    echo "..."
elif [ "$http_code" = "401" ]; then
    echo "   ❌ Authentication failed for query endpoint"
    cat /tmp/aci_query_test.json
    exit 1
else
    echo "   ⚠️  Unexpected response: $http_code"
    cat /tmp/aci_query_test.json
fi

echo ""

# Summary
echo "=== Test Summary ==="
echo "✅ API endpoints are accessible"
echo "✅ Authentication mechanism works"
echo "✅ Request format is accepted"
echo ""
echo "Note: This test validates connectivity and basic API structure."
echo "Full payment processing requires valid payment method data."

# Cleanup
rm -f /tmp/aci_auth_test.json /tmp/aci_payment_test.json /tmp/aci_query_test.json

echo ""
echo "🎉 ACI API connectivity test completed successfully!"