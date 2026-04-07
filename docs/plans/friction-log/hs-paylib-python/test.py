#!/usr/bin/env python3
"""
Test suite for hs-paylib Python server
Tests payment authorization and refund flows for USD (Stripe) and EUR (Adyen)
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"
TEST_RESULTS = []


def log_test(name: str, success: bool, details: dict = None):
    """Log test result"""
    result = {
        "name": name,
        "success": success,
        "timestamp": datetime.now().isoformat(),
        "details": details or {},
    }
    TEST_RESULTS.append(result)
    status = "PASS" if success else "FAIL"
    print(f"  [{status}] {name}")
    if details and not success:
        print(f"       Error: {details.get('error', 'Unknown error')}")
    return success


def test_health_check():
    """Test health check endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return log_test(
                "Health Check",
                True,
                {"stripeConfigured": data.get("stripeConfigured"), "adyenConfigured": data.get("adyenConfigured")},
            )
        else:
            return log_test("Health Check", False, {"status_code": response.status_code})
    except Exception as e:
        return log_test("Health Check", False, {"error": str(e)})


def test_usd_authorize():
    """Test USD payment authorization via Stripe"""
    try:
        payload = {
            "merchant_transaction_id": f"usd_test_{int(time.time())}",
            "amount": 10.00,
            "currency": "USD",
            "card_number": "4111111111111111",
            "card_exp_month": "12",
            "card_exp_year": "2027",
            "card_cvc": "123",
            "card_holder_name": "Test User",
        }

        response = requests.post(f"{BASE_URL}/authorize", json=payload, timeout=30)
        data = response.json()

        if response.status_code == 200 and data.get("success"):
            return log_test(
                "USD Authorization (Stripe)",
                True,
                {
                    "connector": data.get("connector"),
                    "status": data.get("statusText"),
                    "transactionId": data.get("connectorTransactionId"),
                },
            )
        else:
            return log_test(
                "USD Authorization (Stripe)",
                False,
                {"status_code": response.status_code, "error": data.get("detail", "Unknown")},
            )
    except Exception as e:
        return log_test("USD Authorization (Stripe)", False, {"error": str(e)})


def test_eur_authorize():
    """Test EUR payment authorization via Adyen"""
    try:
        payload = {
            "merchant_transaction_id": f"eur_test_{int(time.time())}",
            "amount": 10.00,
            "currency": "EUR",
            "card_number": "4111111111111111",
            "card_exp_month": "12",
            "card_exp_year": "2027",
            "card_cvc": "123",
            "card_holder_name": "Test User",
        }

        response = requests.post(f"{BASE_URL}/authorize", json=payload, timeout=30)
        data = response.json()

        if response.status_code == 200 and data.get("success"):
            return log_test(
                "EUR Authorization (Adyen)",
                True,
                {
                    "connector": data.get("connector"),
                    "status": data.get("statusText"),
                    "transactionId": data.get("connectorTransactionId"),
                },
            )
        else:
            return log_test(
                "EUR Authorization (Adyen)",
                False,
                {"status_code": response.status_code, "error": data.get("detail", "Unknown")},
            )
    except Exception as e:
        return log_test("EUR Authorization (Adyen)", False, {"error": str(e)})


def test_invalid_currency():
    """Test invalid currency rejection"""
    try:
        payload = {
            "merchant_transaction_id": f"invalid_{int(time.time())}",
            "amount": 10.00,
            "currency": "GBP",  # Invalid currency
            "card_number": "4111111111111111",
            "card_exp_month": "12",
            "card_exp_year": "2027",
            "card_cvc": "123",
            "card_holder_name": "Test User",
        }

        response = requests.post(f"{BASE_URL}/authorize", json=payload, timeout=10)

        # Should fail validation
        if response.status_code in [400, 422]:
            return log_test(
                "Invalid Currency Rejection",
                True,
                {"status_code": response.status_code, "rejected": True},
            )
        else:
            return log_test(
                "Invalid Currency Rejection",
                False,
                {"expected": "400 or 422", "got": response.status_code},
            )
    except Exception as e:
        return log_test("Invalid Currency Rejection", False, {"error": str(e)})


def print_summary():
    """Print test summary"""
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in TEST_RESULTS if r["success"])
    failed = sum(1 for r in TEST_RESULTS if not r["success"])
    total = len(TEST_RESULTS)

    print(f"\nTotal: {total} | Passed: {passed} | Failed: {failed}")
    print(f"Success Rate: {passed/total*100:.1f}%" if total > 0 else "N/A")

    if failed > 0:
        print("\nFailed Tests:")
        for result in TEST_RESULTS:
            if not result["success"]:
                print(f"  - {result['name']}")

    print("\n" + "=" * 60)


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("hs-paylib Python Server Test Suite")
    print("=" * 60)
    print(f"\nTesting against: {BASE_URL}")
    print("Make sure the server is running: python main.py\n")

    # Run tests
    test_health_check()
    test_usd_authorize()
    test_eur_authorize()
    test_invalid_currency()

    # Print summary
    print_summary()

    # Return exit code
    failed = sum(1 for r in TEST_RESULTS if not r["success"])
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
