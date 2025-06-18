#[cfg(test)]
mod tests {
    use crate::payments::*;
    use serde_json;

    #[test]
    fn test_string_enum_deserialization() {
        println!("🧪 Testing automatic enum string deserialization with g2h");
        
        // Test PaymentsAuthorizeRequest with string enum values
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
        
        let result: Result<PaymentsAuthorizeRequest, _> = serde_json::from_str(json_with_string_enums);
        
        match result {
            Ok(request) => {
                println!("\n✅ Successfully deserialized:");
                println!("  Amount: {}", request.amount);
                println!("  Currency: {} (should be USD enum value)", request.currency);
                println!("  Payment Method: {} (should be CARD enum value)", request.payment_method);
                println!("  Auth Type: {} (should be THREE_DS enum value)", request.auth_type);
                
                // Verify the enum values are correct integers
                assert_eq!(request.amount, 1000);
                // Currency values will depend on the enum definitions, but should be valid integers
                assert!(request.currency >= 0);
                assert!(request.payment_method >= 0);
                assert!(request.auth_type >= 0);
            }
            Err(e) => {
                panic!("❌ Failed to deserialize string enums: {}", e);
            }
        }
    }

    #[test]
    fn test_integer_enum_deserialization() {
        // Test with integer enum values (should still work)
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
        
        let result: Result<PaymentsAuthorizeRequest, _> = serde_json::from_str(json_with_int_enums);
        
        match result {
            Ok(request) => {
                println!("\n✅ Successfully deserialized:");
                println!("  Amount: {}", request.amount);
                println!("  Currency: {} (integer enum value)", request.currency);
                println!("  Payment Method: {} (integer enum value)", request.payment_method);
                println!("  Auth Type: {} (integer enum value)", request.auth_type);
                
                assert_eq!(request.amount, 2000);
                assert_eq!(request.currency, 0);
                assert_eq!(request.payment_method, 1);
                assert_eq!(request.auth_type, 2);
            }
            Err(e) => {
                panic!("❌ Failed to deserialize integer enums: {}", e);
            }
        }
    }
}