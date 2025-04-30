#!/usr/bin/env python3
from payments import authorize_payment, sync_payment, get_payment_details
from payment_pb2 import Connector, Currency
import os

# Razorpay test credentials
RAZORPAY_API_KEY = "<YOUR_RAZORPAY_API_KEY>"  # Replace with your Razorpay API key
RAZORPAY_KEY1 = "<YOUR_RAZORPAY_KEY1>"  # Replace with your Razorpay Key1

def test_payment_flow():
    print("\n=== Testing Payment Flow ===\n")
    
    # Test payment authorization
    print("1. Testing payment authorization...")
    print(f"Using currency: INR (enum value: {Currency.INR})")
    print(f"Using connector: RAZORPAY (enum value: {Connector.RAZORPAY})")
    
    auth_result = authorize_payment(
        amount=1000.00,  # Razorpay expects amount in paise (1000 INR)
        currency="INR",
        connector="RAZORPAY",
        api_key=RAZORPAY_API_KEY,
        payment_method="card",
        card_details={
            "card_number": "5123456789012346",
            "card_exp_month": "12",
            "card_exp_year": "2025",
            "card_cvc": "123"
        },
        email="test@example.com",
        reference_id="order_" + os.urandom(4).hex()  # Adding a unique order ID
    )
    print(f"Authorization result: {auth_result}\n")
    
    if "error" in auth_result:
        print(f"❌ Authorization failed: {auth_result['error']}")
        return
    
    payment_id = auth_result.get("payment_id")
    if not payment_id:
        print("❌ No payment ID received")
        return
        
    # Test payment sync
    print("2. Testing payment sync...")
    sync_result = sync_payment(
        payment_id=payment_id,
        connector="RAZORPAY",
        api_key=RAZORPAY_API_KEY
    )
    print(f"Sync result: {sync_result}\n")
    
    # Test payment details
    print("3. Testing get payment details...")
    details_result = get_payment_details(payment_id=payment_id)
    print(f"Payment details: {details_result}\n")
    
    # Print final status
    print("=== Test Summary ===")
    print("✅ Authorization:", "success" if "error" not in auth_result else "failed")
    print("✅ Sync:", "success" if "error" not in sync_result else "failed")
    print("✅ Details:", "success" if "error" not in details_result else "failed")

if __name__ == "__main__":
    test_payment_flow() 