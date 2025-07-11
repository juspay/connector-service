  ⎿ Detailed Cashfree V3 UPI Implementation Plan (CreateOrder + Authorize Flows)

    Based on the authorization guide, Cashfree V3 analysis, and Razorpay V2 reference patterns, implementing CreateOrder and Authorize flows for UPI Collect and UPI Intent.

    Phase 1: Gateway Registration and System Integration

    Step 1.1: Add Cashfree to ConnectorEnum

    File: backend/domain_types/src/connector_types.rs:42-51
    - Add Cashfree to enum variants after Authorizedotnet
    - Add integer mapping in ForeignTryFrom<grpc_api_types::payments::Connector> (use next available ID)
    - Update gRPC protocol buffer mapping

    Step 1.2: Register in Connector Factory

    File: backend/connector-integration/src/types.rs:4-6, 24-33
    - Add Cashfree import: use crate::connectors::{..., Cashfree};
    - Add to factory: ConnectorEnum::Cashfree => Box::new(Cashfree::new()),

    Step 1.3: Export Module

    File: backend/connector-integration/src/connectors.rs:9-12
    - Add pub mod cashfree;
    - Add cashfree::Cashfree to use statement: pub use self::{..., cashfree::Cashfree};

    Step 1.4: Add Configuration

    File: backend/domain_types/src/types.rs:40-50
    - Add pub cashfree: ConnectorParams, to Connectors struct

    File: config/development.toml:21-31
    - Add cashfree.base_url = "https://sandbox.cashfree.com/"

    Phase 2: Create Connector Structure

    Step 2.1: Main Connector File

    File: backend/connector-integration/src/connectors/cashfree.rs
    #[derive(Clone)]
    pub struct Cashfree {
        pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = String> + Sync),
    }

    impl Cashfree {
        pub const fn new() -> &'static Self {
            &Self {
                amount_converter: &common_utils::types::StringMajorUnitForConnector,
            }
        }
    }

    Step 2.2: ValidationTrait Implementation

    impl interfaces::connector_types::ValidationTrait for Cashfree {
        fn should_do_order_create(&self) -> bool {
            true  // Cashfree V3 requires order creation
        }
    }

    Step 2.3: ConnectorCommon Implementation

    - id() returns "cashfree"
    - get_currency_unit() returns CurrencyUnit::Base (for major units)
    - base_url() returns &connectors.cashfree.base_url
    - get_auth_header() implements V3 API key headers
    - build_error_response() handles Cashfree error format

    Phase 3: Authentication Implementation

    Step 3.1: Authentication Types

    File: backend/connector-integration/src/connectors/cashfree/transformers.rs
    #[derive(Debug)]
    pub enum CashfreeAuthType {
        ApiKeySecret {
            app_id: Secret<String>,    // X-Client-Id
            secret_key: Secret<String>, // X-Client-Secret
        },
    }

    impl TryFrom<&ConnectorAuthType> for CashfreeAuthType {
        // Map from BodyKey { api_key, key1 } or SignatureKey patterns
    }

    Step 3.2: Header Generation

    fn get_auth_header() -> Vec<(String, Maskable<String>)> {
        vec![
            ("X-Client-Id".to_string(), auth.app_id.peek().into()),
            ("X-Client-Secret".to_string(), auth.secret_key.peek().into()),
            ("x-api-version".to_string(), "2022-09-01".into()),
            ("Content-Type".to_string(), "application/json".into()),
        ]
    }

    Phase 4: CreateOrder Flow Implementation

    Step 4.1: CreateOrder Request Structure

    #[derive(Debug, Serialize)]
    pub struct CashfreeOrderCreateRequest {
        pub order_id: String,           // Transaction ID
        pub order_amount: f64,          // Major unit amount
        pub order_currency: String,     // Default "INR"
        pub customer_details: CashfreeCustomerDetails,
        pub order_meta: CashfreeOrderMeta,
        pub order_note: Option<String>,
        pub order_expiry_time: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct CashfreeCustomerDetails {
        pub customer_id: String,
        pub customer_email: Option<String>,
        pub customer_phone: String,
        pub customer_name: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct CashfreeOrderMeta {
        pub return_url: String,
        pub notify_url: String,
        pub payment_methods: Option<String>,
    }

    Step 4.2: CreateOrder Response Structure

    #[derive(Debug, Deserialize)]
    pub struct CashfreeOrderCreateResponse {
        pub payment_session_id: String,  // KEY: Used in Authorize flow
        pub cf_order_id: i32,
        pub order_id: String,
        pub order_amount: f64,
        pub order_currency: String,
        pub order_status: String,
        pub customer_details: CashfreeCustomerDetails,
        pub order_meta: CashfreeOrderMeta,
    }

    Step 4.3: CreateOrder ConnectorIntegrationV2

    impl ConnectorIntegrationV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Cashfree {
        fn get_headers() -> Vec<(String, Maskable<String>)>
        fn get_url() -> String { format!("{base_url}/pg/orders") }
        fn get_request_body() -> CashfreeOrderCreateRequest
        fn handle_response_v2() -> PaymentCreateOrderResponse
    }

    Phase 5: Authorize Flow Implementation

    Step 5.1: Authorize Request Structure

    #[derive(Debug, Serialize)]
    pub struct CashfreePaymentRequest {
        pub payment_session_id: String,  // From CreateOrder response
        pub payment_method: CashfreePaymentMethod,
        pub payment_surcharge: Option<CashfreePaymentSurcharge>,
    }

    #[derive(Debug, Serialize)]
    pub struct CashfreePaymentMethod {
        pub upi: Option<CashfreeUpiDetails>,
        // All other methods set to None
    }

    #[derive(Debug, Serialize)]
    pub struct CashfreeUpiDetails {
        pub channel: String,    // "link" for Intent, "collect" for Collect
        pub upi_id: String,     // VPA for collect, empty for intent
    }

    Step 5.2: UPI Flow Determination Logic

    fn determine_upi_flow(payment_method_data: &PaymentMethodData) -> UpiFlow {
        match payment_method_data {
            PaymentMethodData::Upi(UpiData::UpiCollect(details)) => {
                // Collect flow: has VPA
                UpiFlow::Collect(details.vpa_id.clone())
            },
            PaymentMethodData::Upi(UpiData::UpiIntent(_)) => {
                // Intent flow: no VPA needed
                UpiFlow::Intent
            },
            _ => UpiFlow::Intent, // Default
        }
    }

    Step 5.3: Authorize Response Structure

    #[derive(Debug, Deserialize)]
    pub struct CashfreePaymentResponse {
        pub payment_method: String,
        pub channel: String,
        pub action: String,
        pub data: CashfreeResponseData,
        pub cf_payment_id: Option<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CashfreeResponseData {
        pub url: Option<String>,
        pub payload: Option<CashfreePayloadData>,
        pub content_type: Option<String>,
        pub method: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CashfreePayloadData {
        #[serde(rename = "default")]
        pub default_link: String,    // Universal deep link for Intent
        pub gpay: Option<String>,
        pub phonepe: Option<String>,
        pub paytm: Option<String>,
        pub bhim: Option<String>,
    }

    Step 5.4: Authorize ConnectorIntegrationV2

    impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Cashfree {
        fn get_headers() -> Vec<(String, Maskable<String>)>
        fn get_url() -> String { format!("{base_url}/pg/orders/sessions") }
        fn get_request_body() -> CashfreePaymentRequest
        fn handle_response_v2() -> PaymentsResponseData
    }

    Phase 6: Request/Response Transformations

    Step 6.1: CreateOrder Request Transformation

    impl TryFrom<&RouterDataV2<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse>> for CashfreeOrderCreateRequest {
        fn try_from(item: &RouterDataV2<...>) -> Result<Self, ConnectorError> {
            let connector = Cashfree::new();
            let amount = connector.amount_converter.convert(
                item.request.amount, 
                item.request.currency
            )?;
            
            Ok(Self {
                order_id: item.payment_id.clone(),
                order_amount: amount.parse()?,
                order_currency: item.request.currency.to_string(),
                customer_details: build_customer_details(item)?,
                order_meta: build_order_meta(item)?,
                order_note: item.request.description.clone(),
                order_expiry_time: None,
            })
        }
    }

    Step 6.2: Authorize Request Transformation

    impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> for CashfreePaymentRequest {
        fn try_from(item: &RouterDataV2<...>) -> Result<Self, ConnectorError> {
            let payment_session_id = item.resource_common_data
                .connector_request_reference_id
                .clone()
                .ok_or(ConnectorError::MissingRequiredField { field_name: "payment_session_id" })?;
                
            let upi_flow = determine_upi_flow(&item.request.payment_method_data)?;
            let payment_method = build_upi_payment_method(upi_flow)?;
            
            Ok(Self {
                payment_session_id,
                payment_method,
                payment_surcharge: None, // Add surcharge logic if needed
            })
        }
    }

    Step 6.3: Response Transformations

    // CreateOrder Response
    impl TryFrom<CashfreeOrderCreateResponse> for PaymentCreateOrderResponse {
        fn try_from(response: CashfreeOrderCreateResponse) -> Result<Self, ConnectorError> {
            Ok(Self {
                connector_order_id: Some(response.payment_session_id.clone()),
                payment_session_id: Some(response.payment_session_id),
                status: response.order_status,
                // ... other fields
            })
        }
    }

    // Authorize Response
    impl TryFrom<CashfreePaymentResponse> for PaymentsResponseData {
        fn try_from(response: CashfreePaymentResponse) -> Result<Self, ConnectorError> {
            match response.channel.as_str() {
                "link" => {
                    // Intent flow - extract deep link
                    let deep_link = response.data.payload
                        .and_then(|p| Some(p.default_link))
                        .ok_or(ConnectorError::MissingRequiredField { field_name: "intent_link" })?;
                        
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(response.cf_payment_id.unwrap_or_default().to_string()),
                        redirection_data: Some(RedirectionData::new_with_intent_url(deep_link)),
                        // ... other fields
                    })
                },
                "collect" => {
                    // Collect flow - return collect response
                    Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::ConnectorTransactionId(response.cf_payment_id.unwrap_or_default().to_string()),
                        redirection_data: None,
                        // ... other fields
                    })
                },
                _ => Err(ConnectorError::ResponseDeserializationFailed),
            }
        }
    }

    Phase 7: Framework Integration

    Step 7.1: AmountConvertor Integration

    - Use StringMajorUnitForConnector for decimal string amounts (e.g., "10.50")
    - Implement in both CreateOrder and Authorize request transformations
    - Handle currency-specific formatting

    Step 7.2: Integrity Framework Integration

    - Replace integrity_object: None with actual integrity objects in domain types
    - Implement GetIntegrityObject trait for both flows
    - Extract and validate integrity data from responses

    Step 7.3: Source Verification Framework Integration

    - Implement basic API key-based verification
    - Use HmacSha256 algorithm for signature verification
    - Handle webhook signature validation

    Phase 8: Error Handling

    Step 8.1: Error Response Structure

    #[derive(Debug, Deserialize)]
    pub struct CashfreeErrorResponse {
        pub message: String,
        pub code: String,
        #[serde(rename = "type")]
        pub error_type: String,
    }

    Step 8.2: Error Mapping in build_error_response

    fn build_error_response(res: Response) -> ErrorResponse {
        let error: CashfreeErrorResponse = res.response.parse_struct("CashfreeErrorResponse")?;
        
        let attempt_status = match error.code.as_str() {
            "AUTHENTICATION_ERROR" => AttemptStatus::AuthenticationFailed,
            "AUTHORIZATION_ERROR" => AttemptStatus::AuthorizationFailed,
            "INVALID_REQUEST_ERROR" => AttemptStatus::Failure,
            "GATEWAY_ERROR" => AttemptStatus::Failure,
            "SERVER_ERROR" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };
        
        ErrorResponse {
            code: error.code,
            message: error.message.clone(),
            reason: Some(error.message),
            status_code: res.status_code,
            attempt_status: Some(attempt_status),
            // ... other fields
        }
    }

    Phase 9: UPI Flow Implementations

    Step 9.1: UPI Intent Flow Processing

    fn process_upi_intent_response(response: CashfreePaymentResponse) -> PaymentsResponseData {
        let deep_link = extract_intent_deep_link(response)?;
        let trimmed_link = truncate_intent_link(deep_link, "?")?;
        
        PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.cf_payment_id.to_string()),
            redirection_data: Some(RedirectionData::new_with_intent_url(trimmed_link)),
            mandate_reference: None,
            connector_metadata: None,
            network_transaction_id: None,
            // ... other fields
        }
    }

    Step 9.2: UPI Collect Flow Processing

    fn process_upi_collect_response(response: CashfreePaymentResponse) -> PaymentsResponseData {
        PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.cf_payment_id.to_string()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: Some(build_collect_metadata(response)?),
            network_transaction_id: None,
            // ... other fields
        }
    }

    Phase 10: Trait Implementations

    Step 10.1: Required Service Traits

    impl connector_types::ConnectorServiceTrait for Cashfree {}
    impl connector_types::PaymentAuthorizeV2 for Cashfree {}
    impl connector_types::PaymentOrderCreate for Cashfree {}

    Step 10.2: Framework Trait Stubs

    // Source Verification stubs (implement properly in final phase)
    impl SourceVerification<CreateOrder, PaymentFlowData, PaymentCreateOrderData, PaymentCreateOrderResponse> for Cashfree {
        fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
            Ok(Vec::new()) // Stub implementation
        }
        // ... other methods
    }

    // Similar stubs for Authorize flow and other required flows

    Step 10.3: Unsupported Flow Stubs

    impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Cashfree {}
    impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Cashfree {}
    impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Cashfree {}
    impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Cashfree {}
    // ... other unsupported flows

    Implementation Order Summary

    1. Gateway Registration (Phase 1) - Get system to recognize Cashfree
    2. Basic Connector Structure (Phase 2) - Create foundation with AmountConvertor
    3. Authentication (Phase 3) - V3 API key header implementation
    4. CreateOrder Flow (Phase 4) - Order creation with session ID
    5. Authorize Flow (Phase 5) - UPI Intent/Collect transaction processing
    6. Transformations (Phase 6) - Request/response mapping logic
    7. Framework Integration (Phase 7) - AmountConvertor, Integrity, Source Verification
    8. Error Handling (Phase 8) - Comprehensive error mapping
    9. UPI Specifics (Phase 9) - Intent and Collect flow processing
    10. Trait Implementation (Phase 10) - Required traits and stubs for compilation

    This implementation covers the two essential flows (CreateOrder + Authorize) needed for Cashfree V3 UPI Collect and UPI Intent functionality, following the authorization guide's patterns while leveraging Cashfree's specific V3 
    architecture.