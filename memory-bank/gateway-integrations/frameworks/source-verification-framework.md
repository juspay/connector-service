# Source Verification Framework

## Overview

The Source Verification framework provides cryptographic verification of requests, responses, and webhooks to ensure they originate from legitimate sources and haven't been tampered with. It validates API responses and webhook signatures using connector-specific cryptographic methods.

**⚠️ Important**: Currently, most connectors use default empty implementations (`NoAlgorithm`, empty secrets), which bypasses verification entirely. This guide shows how to implement it correctly.

## Core Trait

```rust
pub trait SourceVerification<Flow, ResourceCommonData, Req, Resp> {
    fn get_secrets(
        &self,
        secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError>;

    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, domain_types::errors::ConnectorError>;

    fn get_signature(
        &self,
        payload: &[u8],
        router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>,
        secrets: &[u8],
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError>;

    fn get_message(
        &self,
        payload: &[u8],
        router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>,
        secrets: &[u8],
    ) -> CustomResult<Vec<u8>, domain_types::errors::ConnectorError>;

    fn verify(
        &self,
        router_data: &RouterDataV2<Flow, ResourceCommonData, Req, Resp>,
        secrets: ConnectorSourceVerificationSecrets,
        payload: &[u8],
    ) -> CustomResult<bool, domain_types::errors::ConnectorError>;
}
```

## Secret Types

```rust
pub enum ConnectorSourceVerificationSecrets {
    AuthHeaders(ConnectorAuthType),
    WebhookSecret(ConnectorWebhookSecrets),
    AuthWithWebHookSecret {
        auth_headers: ConnectorAuthType,
        webhook_secret: ConnectorWebhookSecrets,
    },
}
```

## Integration with ConnectorIntegrationV2

Every connector automatically implements SourceVerification:

```rust
pub trait ConnectorIntegrationV2<Flow, ResourceCommonData, Req, Resp>:
    ConnectorIntegrationAnyV2<Flow, ResourceCommonData, Req, Resp>
    + Sync
    + api::ConnectorCommon
    + SourceVerification<Flow, ResourceCommonData, Req, Resp>
{
    // All connector methods...
}
```

## Webhook Verification Usage

```rust
// In webhook processing
impl IncomingWebhook for Adyen {
    fn verify_webhook_source(
        &self,
        request: RequestDetails,
        connector_webhook_secret: Option<ConnectorWebhookSecrets>,
        _connector_account_details: Option<ConnectorAuthType>,
    ) -> Result<bool, ConnectorError> {
        let webhook_signature = request
            .headers
            .get("authorization")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        let signature_components = webhook_signature
            .split(',')
            .collect::<HashMap<&str, &str>>();

        let hmac_signature = signature_components
            .get("signature")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        // Create HMAC verifier with webhook secret
        let algorithm = crypto::HmacSha256::new(webhook_secret.as_bytes());
        
        // Verify signature against request body
        algorithm.verify_signature(
            hmac_signature.as_bytes(),
            &request.body,
        )
    }
}
```

## Cryptographic Support

The framework supports multiple verification algorithms:
- **HMAC-SHA256**: For webhook signature verification
- **RSA-SHA256**: For certificate-based verification  
- **Custom Algorithms**: Connector-specific signature schemes

## Benefits
- **Security**: Prevents man-in-the-middle attacks and payload tampering
- **Authenticity**: Ensures requests/responses come from legitimate sources
- **Fraud Prevention**: Blocks forged webhook events and API responses
- **Compliance**: Meets security requirements for payment processing

## Framework Integration Pattern

### Connector Implementation

Connectors use macros to automatically implement all three frameworks:

```rust
macros::create_all_prerequisites!(
    connector_name: Adyen,
    api: [
        (
            flow: Authorize,
            request_body: AdyenPaymentRequest,
            response_body: AdyenPaymentResponse,
            router_data: RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>
        ),
        // ... other flows
    ],
    amount_converters: [
        amount_converter: StringMajorUnit  // Adyen uses string major units
    ],
    member_functions: {
        // Custom connector-specific functions
    }
);
```

### Payment Processing Pipeline

The frameworks work together in the payment processing pipeline:

1. **Request Phase**:
   - AmountConvertor converts amounts to connector format
   - SourceVerification validates request authenticity
   - IntegrityFramework captures request integrity object

2. **Processing Phase**:
   - Connector processes request with converted amounts
   - Response received from payment processor

3. **Response Phase**:
   - SourceVerification validates response authenticity
   - IntegrityFramework compares request vs response data
   - AmountConvertor converts response amounts back to standard format

4. **Webhook Phase**:
   - SourceVerification validates webhook signatures
   - IntegrityFramework ensures webhook data consistency
   - AmountConvertor handles webhook amount fields

## Connector Integration Guide

### 🚀 Quick Start for New Connectors

When integrating a new connector, you MUST implement source verification in 4 methods to enable actual cryptographic validation:

#### **Step 1: Extract Secrets**
**Location**: `/backend/connector-integration/src/connectors/{connector}.rs`

```rust
impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for YourConnector {
    fn get_secrets(
        &self,
        secrets: ConnectorSourceVerificationSecrets,
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        match secrets {
            ConnectorSourceVerificationSecrets::AuthHeaders(auth) => {
                match auth {
                    ConnectorAuthType::HeaderKey { api_key } => Ok(api_key.into_bytes()),
                    ConnectorAuthType::BodyKey { api_key, key1 } => {
                        // Combine keys for verification
                        Ok(format!("{}:{}", api_key.peek(), key1.peek()).into_bytes())
                    }
                    _ => Ok(Vec::new()),
                }
            }
            ConnectorSourceVerificationSecrets::WebhookSecret(webhook_secret) => {
                Ok(webhook_secret.secret.into_bytes())
            }
            ConnectorSourceVerificationSecrets::AuthWithWebHookSecret { webhook_secret, .. } => {
                Ok(webhook_secret.secret.into_bytes())
            }
        }
    }
}
```

#### **Step 2: Select Algorithm**
**Location**: Same file as Step 1

```rust
    fn get_algorithm(
        &self,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        // Choose appropriate algorithm based on connector requirements
        
        // For HMAC-SHA256 (most common for webhooks)
        Ok(Box::new(crypto::HmacSha256))
        
        // For RSA-SHA256 (certificate-based verification)
        // Ok(Box::new(crypto::RsaSha256))
        
        // For custom algorithms, implement VerifySignature trait
        // Ok(Box::new(YourCustomAlgorithm))
    }
```

#### **Step 3: Extract Signature**
**Location**: Same file as Step 1

```rust
    fn get_signature(
        &self,
        payload: &[u8],
        router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // Option 1: Extract from response headers
        if let Some(signature_header) = router_data.response.headers.get("x-signature") {
            return Ok(signature_header.as_bytes().to_vec());
        }
        
        // Option 2: Extract from response body
        let response: YourConnectorResponse = serde_json::from_slice(payload)
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        
        if let Some(signature) = response.signature {
            return hex::decode(signature)
                .change_context(ConnectorError::ResponseDeserializationFailed);
        }
        
        // Option 3: Generate expected signature for comparison
        let expected_signature = self.calculate_expected_signature(payload, secrets)?;
        Ok(expected_signature)
    }
```

#### **Step 4: Prepare Message**
**Location**: Same file as Step 1

```rust
    fn get_message(
        &self,
        payload: &[u8],
        router_data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
        secrets: &[u8],
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        // Option 1: Use raw payload (default)
        Ok(payload.to_owned())
        
        // Option 2: Create canonical message for verification
        let canonical_message = format!(
            "{}|{}|{}|{}",
            router_data.request.payment_id,
            router_data.request.amount,
            router_data.request.currency,
            std::str::from_utf8(payload).unwrap_or_default()
        );
        Ok(canonical_message.into_bytes())
        
        // Option 3: Extract specific fields for message construction
        let response: YourConnectorResponse = serde_json::from_slice(payload)
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        
        let message = format!(
            "{}{}{}",
            response.transaction_id.unwrap_or_default(),
            response.amount.unwrap_or_default(),
            response.status.unwrap_or_default()
        );
        Ok(message.into_bytes())
    }
```

### 🔧 **Implementation Examples by Connector Type**

#### **HMAC-based Verification (Most Common)**
```rust
// For connectors like Stripe, PayPal, Adyen webhooks
impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for YourConnector {
    fn get_secrets(&self, secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
        match secrets {
            ConnectorSourceVerificationSecrets::WebhookSecret(webhook_secret) => {
                Ok(webhook_secret.secret.into_bytes())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_signature(&self, payload: &[u8], router_data: &RouterDataV2<...>, secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        // Extract signature from webhook header
        router_data.request.headers
            .get("x-webhook-signature")
            .map(|sig| hex::decode(sig.strip_prefix("sha256=").unwrap_or(sig)))
            .transpose()
            .change_context(ConnectorError::WebhookSignatureNotFound)?
            .ok_or(ConnectorError::WebhookSignatureNotFound.into())
    }

    fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<...>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        Ok(payload.to_owned()) // Verify the raw payload
    }
}
```

#### **API Key-based Verification**
```rust
// For connectors that use API key validation
impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for YourConnector {
    fn get_secrets(&self, secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
        match secrets {
            ConnectorSourceVerificationSecrets::AuthHeaders(ConnectorAuthType::HeaderKey { api_key }) => {
                Ok(api_key.into_bytes())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_signature(&self, payload: &[u8], _router_data: &RouterDataV2<...>, secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        // Generate expected signature using API key
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.update(secrets);
        Ok(hasher.finalize().to_vec())
    }

    fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<...>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        Ok(payload.to_owned())
    }
}
```

#### **Certificate-based Verification**
```rust
// For connectors using RSA/certificate verification
impl SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for YourConnector {
    fn get_secrets(&self, secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
        match secrets {
            ConnectorSourceVerificationSecrets::AuthHeaders(auth) => {
                // Extract public key from auth config
                match auth {
                    ConnectorAuthType::CertificateAuth { certificate, .. } => {
                        Ok(certificate.into_bytes())
                    }
                    _ => Ok(Vec::new()),
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        Ok(Box::new(crypto::RsaSha256))
    }

    fn get_signature(&self, payload: &[u8], router_data: &RouterDataV2<...>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        // Extract RSA signature from response
        let response: YourConnectorResponse = serde_json::from_slice(payload)
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        
        base64::decode(response.signature.ok_or(ConnectorError::ResponseDeserializationFailed)?)
            .change_context(ConnectorError::ResponseDeserializationFailed)
    }

    fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<...>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
        // Create canonical message for RSA verification
        let response: YourConnectorResponse = serde_json::from_slice(payload)
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        
        let canonical = format!(
            "{}.{}.{}",
            response.transaction_id.unwrap_or_default(),
            response.amount.unwrap_or_default(),
            response.timestamp.unwrap_or_default()
        );
        Ok(canonical.into_bytes())
    }
}
```

### 🧪 **Testing Your Implementation**

#### **Unit Tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_source_verification_success() {
        let connector = YourConnector;
        let router_data = create_test_router_data();
        let secrets = ConnectorSourceVerificationSecrets::WebhookSecret(
            ConnectorWebhookSecrets {
                secret: "test_secret_key".to_string(),
            }
        );
        
        // Mock valid response with correct signature
        let payload = create_valid_signed_payload();
        
        let result = connector.verify(&router_data, secrets, &payload);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_source_verification_failure() {
        let connector = YourConnector;
        let router_data = create_test_router_data();
        let secrets = ConnectorSourceVerificationSecrets::WebhookSecret(
            ConnectorWebhookSecrets {
                secret: "test_secret_key".to_string(),
            }
        );
        
        // Mock invalid response with wrong signature
        let payload = create_invalid_signed_payload();
        
        let result = connector.verify(&router_data, secrets, &payload);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Verification should fail
    }
}
```

#### **Integration Tests**
```bash
# Test end-to-end verification
cargo test --test integration_tests -- test_webhook_verification
cargo test --test integration_tests -- test_api_response_verification
```

### ✅ **Implementation Checklist**

Before marking your connector as "source-verification-ready":

- [ ] **Secret Extraction**: Implemented `get_secrets()` to extract actual connector secrets
- [ ] **Algorithm Selection**: Implemented `get_algorithm()` with appropriate crypto algorithm (not `NoAlgorithm`)
- [ ] **Signature Extraction**: Implemented `get_signature()` to extract/generate verification signatures
- [ ] **Message Preparation**: Implemented `get_message()` with connector-specific message format
- [ ] **Unit Tests**: Added tests for both successful and failed verification scenarios
- [ ] **Integration Tests**: Verified end-to-end verification works with real connector responses
- [ ] **Error Handling**: Graceful handling of missing signatures, invalid formats, etc.
- [ ] **Documentation**: Updated connector docs with verification implementation details

### 🚨 **Common Pitfalls**

1. **Using Default Implementations**: Never leave methods with default empty implementations
2. **Wrong Algorithm**: Ensure algorithm matches connector's verification method
3. **Signature Format**: Handle base64, hex, or raw byte signatures correctly
4. **Message Construction**: Use exact same message format as connector expects
5. **Secret Management**: Ensure secrets are properly extracted from auth config
6. **Header Parsing**: Correctly parse signature headers (e.g., "sha256=abcd1234")
7. **Timestamp Validation**: Some connectors require timestamp-based verification

### 🔍 **Debugging Verification Issues**

When verification fails:

1. **Check Logs**: Look for `SourceVerificationFailed` errors
2. **Verify Secrets**: Ensure secrets are correctly extracted
3. **Algorithm Match**: Confirm algorithm matches connector requirements
4. **Message Format**: Log the message being verified vs expected format
5. **Signature Format**: Check if signature needs base64/hex decoding
6. **Test with Known Good**: Use connector's test/sandbox environment with known signatures

### 📋 **Verification by Use Case**

#### **Webhook Verification**
- Primary use case for source verification
- Validates incoming webhook events from payment processors
- Prevents replay attacks and forged events
- Example: Stripe webhook signatures, PayPal IPN verification

#### **API Response Verification**
- Validates responses from connector APIs
- Ensures responses haven't been tampered with
- Less common but important for high-security environments
- Example: Signature validation on payment status responses

#### **Request Authentication**
- Validates outgoing request signatures
- Ensures connector can authenticate our requests
- Usually handled by request signing rather than response verification
- Example: OAuth signature validation, API key verification

## Best Practices for Connector Developers

1. **Always Implement Source Verification**:
   - Never use default empty implementations in production
   - Always verify webhook signatures to prevent fraud
   - Use connector-specific secret management
   - Handle multiple signature formats when needed

2. **Security Considerations**:
   - Store secrets securely and never log them
   - Use constant-time comparison for signature validation
   - Implement proper error handling without leaking information
   - Consider replay attack prevention with timestamps

3. **Testing and Validation**:
   - Test with both valid and invalid signatures
   - Verify against connector's test environment
   - Document connector-specific verification requirements
   - Include verification in integration test suites

## Framework Benefits

- **Security**: Prevents man-in-the-middle attacks and payload tampering
- **Authenticity**: Ensures requests/responses come from legitimate sources  
- **Fraud Prevention**: Blocks forged webhook events and API responses
- **Compliance**: Meets security requirements for payment processing
- **Consistency**: Standardized approach across all connectors
- **Maintainability**: Centralized framework logic reduces code duplication
- **Extensibility**: Easy to add new connectors following established patterns

The Source Verification framework forms a critical security foundation for payment processing, ensuring all communication with external payment processors is authentic and tamper-proof.