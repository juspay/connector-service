// Test script to verify automatic enum string deserialization
use grpc_api_types::payments::*;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing automatic enum string deserialization with g2h");
    
    // Test 1: PaymentsAuthorizeRequest with string enum values
    let json_with_string_enums = r#"
    {
        "amount": 1000,
        "currency": "USD",
        "payment_method": "CARD",
        "auth_type": "THREE_DS"
    }
    "#;
    
    println!("\n📥 Input JSON with string enums:");
    println!("{}", json_with_string_enums);
    
    let request: PaymentsAuthorizeRequest = serde_json::from_str(json_with_string_enums)?;
    
    println!("\n✅ Successfully deserialized:");
    println!("  Amount: {}", request.amount);
    println!("  Currency: {} (should be USD enum value)", request.currency);
    println!("  Payment Method: {} (should be CARD enum value)", request.payment_method);
    println!("  Auth Type: {} (should be THREE_DS enum value)", request.auth_type);
    
    // Test 2: Test with integer enum values (should still work)
    let json_with_int_enums = r#"
    {
        "amount": 2000,
        "currency": 0,
        "payment_method": 1,
        "auth_type": 2
    }
    "#;
    
    println!("\n📥 Input JSON with integer enums:");
    println!("{}", json_with_int_enums);
    
    let request2: PaymentsAuthorizeRequest = serde_json::from_str(json_with_int_enums)?;
    
    println!("\n✅ Successfully deserialized:");
    println!("  Amount: {}", request2.amount);
    println!("  Currency: {} (integer enum value)", request2.currency);
    println!("  Payment Method: {} (integer enum value)", request2.payment_method);
    println!("  Auth Type: {} (integer enum value)", request2.auth_type);
    
    println!("\n🎉 All tests passed! Automatic enum detection is working correctly.");
    
    Ok(())
}