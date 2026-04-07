#!/bin/bash
# Quick test script for hs-paylib Python server

BASE_URL="http://localhost:8000"

echo "=================================="
echo "hs-paylib Python Server Test"
echo "=================================="
echo ""

# Check if server is running
echo "Checking server health..."
HEALTH=$(curl -s $BASE_URL/health)
echo "Health: $HEALTH"
echo ""

# Test USD payment
echo "Testing USD payment (Stripe)..."
USD_RESPONSE=$(curl -s -X POST $BASE_URL/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "merchant_transaction_id": "usd_test_'$(date +%s)'",
    "amount": 10.00,
    "currency": "USD",
    "card_number": "4111111111111111",
    "card_exp_month": "12",
    "card_exp_year": "2027",
    "card_cvc": "123",
    "card_holder_name": "Test User"
  }')
echo "Response: $USD_RESPONSE"
echo ""

# Test EUR payment
echo "Testing EUR payment (Adyen)..."
EUR_RESPONSE=$(curl -s -X POST $BASE_URL/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "merchant_transaction_id": "eur_test_'$(date +%s)'",
    "amount": 10.00,
    "currency": "EUR",
    "card_number": "4111111111111111",
    "card_exp_month": "12",
    "card_exp_year": "2027",
    "card_cvc": "123",
    "card_holder_name": "Test User"
  }')
echo "Response: $EUR_RESPONSE"
echo ""

echo "=================================="
echo "Tests complete!"
echo "=================================="
