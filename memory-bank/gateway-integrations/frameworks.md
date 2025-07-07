# Gateway Integration Frameworks

## Overview

The Connector Service implements three core frameworks that ensure secure, consistent, and accurate payment processing across all connector integrations. These frameworks handle the fundamental aspects of payment gateway integration: amount handling, data integrity, and security verification.

## 1. AmountConvertor Framework

### Purpose
The AmountConvertor framework standardizes amount handling across different payment processors, which have varying requirements for amount formats and currency representations.

### Core Trait

```rust
pub trait AmountConvertor: Send {
    type Output;
    
    fn convert(
        &self,
        amount: MinorUnit,
        currency: enums::Currency,
    ) -> Result<Self::Output, error_stack::Report<ParsingError>>;

    fn convert_back(
        &self,
        amount: Self::Output,
        currency: enums::Currency,
    ) -> Result<MinorUnit, error_stack::Report<ParsingError>>;
}
```

### Available Implementations

1. **StringMinorUnitForConnector**: Converts amounts to string representation in minor units (cents)
   - Example: $10.50 → "1050"
   - Used by: Connectors that expect string amounts in smallest currency unit

2. **StringMajorUnitForConnector**: Converts amounts to string representation in major units (dollars)
   - Example: $10.50 → "10.50"
   - Used by: Adyen and other connectors expecting decimal string amounts

3. **FloatMajorUnitForConnector**: Converts amounts to float representation in major units
   - Example: $10.50 → 10.50 (float)
   - Used by: Connectors with numeric amount fields

4. **MinorUnitForConnector**: Pass-through for minor units (no conversion)
   - Example: $10.50 → 1050 (integer)
   - Used by: Razorpay and other connectors expecting integer cents

### Integration with Connectors

#### Connector Definition
```rust
#[derive(Clone)]
pub struct Adyen {
    pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = String> + Sync),
}

impl Adyen {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &common_utils::types::StringMajorUnitForConnector,
        }
    }
}
```

#### Usage in Request Transformation
```rust
// From Elavon connector transformer
fn build_payment_request(
    request_data: &PaymentsAuthorizeData,
    connector: &Elavon,
) -> Result<ElavonPaymentRequest> {
    let amount = connector
        .amount_converter
        .convert(request_data.minor_amount, request_data.currency)
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    
    Ok(ElavonPaymentRequest {
        ssl_amount: amount,
        ssl_currency_code: request_data.currency.to_string(),
        // ... other fields
    })
}
```

#### Currency Handling
The framework automatically handles different currency characteristics:
- **Zero-decimal currencies** (JPY, KRW): No conversion needed
- **Two-decimal currencies** (USD, EUR): Standard /100 conversion
- **Three-decimal currencies** (BHD, KWD): /1000 conversion

### Benefits
- **Consistency**: All connectors receive amounts in their expected format
- **Currency Safety**: Automatic handling of currency-specific decimal places
- **Type Safety**: Compile-time guarantees about amount format conversions
- **Maintainability**: Centralized amount conversion logic

## 2. Integrity Framework

### Purpose
The Integrity Framework ensures data consistency and accuracy throughout the payment processing pipeline by validating that request and response data remain coherent.

### Core Traits

```rust
pub trait FlowIntegrity {
    type IntegrityObject;
    
    fn compare(
        req_integrity_object: Self::IntegrityObject,
        res_integrity_object: Self::IntegrityObject,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}

pub trait GetIntegrityObject<T: FlowIntegrity> {
    fn get_response_integrity_object(&self) -> Option<T::IntegrityObject>;
    fn get_request_integrity_object(&self) -> T::IntegrityObject;
}

pub trait CheckIntegrity<Request, T> {
    fn check_integrity(
        &self,
        request: &Request,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}
```

### Integrity Objects by Flow Type

1. **AuthoriseIntegrityObject**: Validates authorization amounts and currencies
2. **CaptureIntegrityObject**: Ensures capture amounts don't exceed authorization
3. **RefundIntegrityObject**: Validates refund amounts against original payment
4. **PaymentVoidIntegrityObject**: Verifies transaction ID consistency
5. **PaymentSyncIntegrityObject**: Validates sync request data
6. **SetupMandateIntegrityObject**: Verifies mandate setup parameters
7. **AcceptDisputeIntegrityObject**: Validates dispute acceptance data
8. **DefendDisputeIntegrityObject**: Verifies dispute defense parameters
9. **RefundSyncIntegrityObject**: Validates refund sync consistency
10. **SubmitEvidenceIntegrityObject**: Verifies evidence submission data

### Implementation Example

```rust
impl FlowIntegrity for AuthoriseIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        // Validate amount consistency
        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        // Validate currency consistency
        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}
```

### Automatic Integration

The framework is automatically integrated into the payment processing pipeline:

```rust
// In external services - automatically called during payment processing
pub async fn execute_connector_processing_step<T, F, ResourceCommonData, Req, Resp>(
    // ... parameters
) -> CustomResult<RouterDataV2<F, ResourceCommonData, Req, Resp>, ConnectorError>
where
    T: FlowIntegrity,
    Req: Clone + GetIntegrityObject<T> + CheckIntegrity<Req, T>,
{
    // Process connector request/response
    let response_data = connector_integration.handle_response_v2(
        &router_data,
        event_builder.as_mut(),
        res,
    )?;

    // Automatic integrity validation
    response_data.check_integrity(&request, connector_transaction_id)?;

    Ok(response_data)
}
```

### Benefits
- **Data Consistency**: Prevents processing of corrupted or inconsistent data
- **Early Error Detection**: Catches discrepancies before they affect downstream systems
- **Financial Accuracy**: Ensures amount and currency integrity across all operations
- **Audit Trail**: Provides detailed mismatch information for debugging

## 3. SourceVerification Framework

### Purpose
The SourceVerification framework provides cryptographic verification of requests, responses, and webhooks to ensure they originate from legitimate sources and haven't been tampered with.

### Core Trait

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

### Secret Types

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

### Integration with ConnectorIntegrationV2

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

### Webhook Verification Usage

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

### Cryptographic Support

The framework supports multiple verification algorithms:
- **HMAC-SHA256**: For webhook signature verification
- **RSA-SHA256**: For certificate-based verification  
- **Custom Algorithms**: Connector-specific signature schemes

### Benefits
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

## Best Practices

### For Connector Developers

1. **Choose Appropriate AmountConvertor**: 
   - Use StringMajorUnit for decimal-based APIs
   - Use MinorUnit for integer-based APIs
   - Use FloatMajorUnit only when necessary

2. **Implement SourceVerification**:
   - Always verify webhook signatures
   - Use connector-specific secret management
   - Handle multiple signature formats when needed

3. **Support IntegrityFramework**:
   - Ensure response objects include all critical fields
   - Handle partial responses gracefully
   - Provide detailed error information for mismatches

### Framework Benefits

- **Consistency**: Standardized approach across all 6 production connectors
- **Security**: Comprehensive verification for all payment operations
- **Reliability**: Data integrity validation prevents processing errors
- **Maintainability**: Centralized framework logic reduces code duplication
- **Extensibility**: Easy to add new connectors following established patterns

These frameworks form the foundation for secure, reliable, and consistent payment processing across the entire Connector Service ecosystem.