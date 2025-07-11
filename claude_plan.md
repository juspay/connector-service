User approved Claude's plan:
  ⎿  Detailed Paytm UPI Integration Plan - Intent & Collect Only

     Overview

     Implement Paytm UPI Intent and Collect flows using the connector framework's multi-flow architecture:
     - CreateSessionToken Flow: Handle Paytm's initiate transaction (step 1) to get txnToken
     - Authorize Flow: Handle Paytm's process transaction (step 2) using txnToken
     - UPI Flow Types: Intent (deep link generation), Collect (VPA-based collection)
     - QR Flow: Marked as TODO for future implementation

     Key Architecture Decisions

     1. Authentication: Use ConnectorAuthType::SignatureKey with Paytm credentials
     2. Multi-Flow: CreateSessionToken → Authorize (leveraging framework orchestration)
     3. Flow Detection: Route between Intent and Collect based on payment method data
     4. No Macros: Manual trait implementation for better control

     ---
     PHASE 1: CONNECTOR REGISTRATION & FOUNDATION

     Step 1.1: Register Paytm in ConnectorEnum

     File: backend/domain_types/src/connector_types.rs
     What: Add Paytm to the system's connector registry
     How:
     1. Add Paytm variant to ConnectorEnum (line ~42):
     pub enum ConnectorEnum {
         Adyen,
         Razorpay,
         Checkout,
         // ... existing connectors
         Paytm,  // Add this
     }
     2. Add integer mapping in foreign_try_from function (line ~62):
     75 => Ok(Self::Paytm),  // Use next available ID

     Step 1.2: Export Paytm Module

     File: backend/connector-integration/src/connectors.rs
     What: Make Paytm connector available to the system
     How:
     1. Add: pub mod paytm;
     2. Add: pub use self::paytm::Paytm;

     Step 1.3: Add to Connector Factory

     File: backend/connector-integration/src/types.rs
     What: Register Paytm in the connector factory pattern
     How:
     1. Add Paytm to imports (line ~3)
     2. Add factory case: ConnectorEnum::Paytm => Box::new(Paytm::new())

     Step 1.4: Add Configuration Structure

     File: backend/domain_types/src/types.rs
     What: Define Paytm configuration parameters
     How:
     1. Add to Connectors struct: pub paytm: ConnectorParams,

     Step 1.5: Configure Base URLs

     File: config/development.toml
     What: Set Paytm API endpoints
     How:
     paytm.base_url = "https://secure.paytmpayments.com/"
     # For staging: "https://securestage.paytmpayments.com/"

     ---
     PHASE 2: CORE CONNECTOR STRUCTURE

     Step 2.1: Create Main Connector File

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Implement the main Paytm connector structure
     How:
     #[derive(Clone)]
     pub struct Paytm {
         pub(crate) amount_converter: &'static (dyn AmountConvertor<Output = String> + Sync),
     }

     impl Paytm {
         pub const fn new() -> &'static Self {
             &Self {
                 amount_converter: &common_utils::types::StringMajorUnitForConnector,
             }
         }
     }

     Step 2.2: Implement ValidationTrait for Multi-Flow

     File: Same as above
     What: Enable CreateSessionToken and Authorize flows
     How:
     impl connector_types::ValidationTrait for Paytm {
         fn should_do_session_token(&self) -> bool {
             true  // Enable CreateSessionToken flow for Paytm's initiate step
         }
         
         fn should_do_order_create(&self) -> bool {
             false  // Paytm doesn't require separate order creation
         }
     }

     Step 2.3: Implement ConnectorCommon Trait

     File: Same as above
     What: Provide basic connector functionality
     How:
     impl ConnectorCommon for Paytm {
         fn id(&self) -> &'static str { "paytm" }
         
         fn get_currency_unit(&self) -> common_enums::CurrencyUnit {
             common_enums::CurrencyUnit::Minor
         }
         
         fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
             &connectors.paytm.base_url
         }
         
         fn get_auth_header(&self, auth_type: &ConnectorAuthType) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
             let auth = PaytmAuthType::try_from(auth_type)?;
             Ok(vec![
                 ("Content-Type".to_string(), "application/json".into()),
             ])
         }
         
         fn build_error_response(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse, errors::ConnectorError> {
             let response: PaytmErrorResponse = res.response.parse_struct("PaytmErrorResponse")?;
             Ok(ErrorResponse {
                 code: response.error_code.unwrap_or_default(),
                 message: response.error_message.unwrap_or_default(),
                 reason: response.error_description,
                 status_code: res.status_code,
                 attempt_status: Some(enums::AttemptStatus::Failure),
                 connector_transaction_id: response.transaction_id,
             })
         }
     }

     Step 2.4: Implement Service Traits

     File: Same as above
     What: Implement required service traits manually
     How:
     impl connector_types::ConnectorServiceTrait for Paytm {}
     impl connector_types::PaymentAuthorizeV2 for Paytm {}
     impl connector_types::PaymentSessionToken for Paytm {}
     impl connector_types::PaymentSyncV2 for Paytm {}
     // Add other required traits as stub implementations
     impl connector_types::RefundV2 for Paytm {}
     impl connector_types::RefundSyncV2 for Paytm {}
     impl connector_types::PaymentCaptureV2 for Paytm {}
     impl connector_types::PaymentVoidV2 for Paytm {}
     impl connector_types::IncomingWebhook for Paytm {}

     ---
     PHASE 3: AUTHENTICATION IMPLEMENTATION

     Step 3.1: Define Paytm Authentication Structure

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Handle SignatureKey authentication type
     How:
     #[derive(Debug, Clone)]
     pub struct PaytmAuthType {
         pub merchant_id: Secret<String>,     // From api_key
         pub merchant_key: Secret<String>,    // From key1  
         pub website: Secret<String>,         // From api_secret
         pub channel_id: String,              // Hardcoded "WEB"
         pub client_id: Option<String>,       // None as specified
     }

     impl TryFrom<&ConnectorAuthType> for PaytmAuthType {
         type Error = error_stack::Report<errors::ConnectorError>;
         
         fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
             match auth_type {
                 ConnectorAuthType::SignatureKey { api_key, key1, api_secret } => {
                     Ok(Self {
                         merchant_id: api_key.to_owned(),      // merchant_id
                         merchant_key: key1.to_owned(),        // signing key
                         website: api_secret.to_owned(),       // website name
                         channel_id: "WEB".to_string(),        // hardcoded
                         client_id: None,                      // None as specified
                     })
                 },
                 _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
             }
         }
     }

     Step 3.2: Implement Paytm Signature Generation

     File: Same as above
     What: Create signature algorithm from Paytm analysis document
     How:
     pub fn generate_paytm_signature(
         payload: &str,
         merchant_key: &str,
     ) -> CustomResult<String, errors::ConnectorError> {
         // Step 1: Generate 3 random bytes
         let mut rng = rand::thread_rng();
         let salt_bytes: [u8; 3] = rng.gen();
         
         // Step 2: Convert salt to Base64
         let salt_b64 = base64::encode(&salt_bytes);
         
         // Step 3: Create hash input: payload + "|" + base64_salt
         let hash_input = format!("{}|{}", payload, salt_b64);
         
         // Step 4: SHA-256 hash
         let mut hasher = Sha256::new();
         hasher.update(hash_input.as_bytes());
         let sha256_hash = format!("{:x}", hasher.finalize());
         
         // Step 5: Create checksum: sha256_hash + base64_salt
         let checksum = format!("{}{}", sha256_hash, salt_b64);
         
         // Step 6: AES encrypt checksum with merchant key
         let signature = aes_encrypt(&checksum, merchant_key)?;
         
         Ok(signature)
     }

     fn aes_encrypt(data: &str, key: &str) -> CustomResult<String, errors::ConnectorError> {
         // Implement AES CBC encryption with PKCS7 padding
         // Use fixed IV as per Paytm specification
         // Return Base64 encoded result
         // Key size: 128/192/256 based on key length
         // Mode: CBC with PKCS7 padding
         // IV: Fixed IV per Paytm specification
     }

     Step 3.3: Create Request Header Generation

     File: Same as above
     What: Generate Paytm API request headers with signatures
     How:
     pub fn create_paytm_header(
         request_body: &impl serde::Serialize,
         auth: &PaytmAuthType,
     ) -> CustomResult<PaytmRequestHeader, errors::ConnectorError> {
         let payload = serde_json::to_string(request_body)?;
         let signature = generate_paytm_signature(&payload, auth.merchant_key.peek())?;
         let timestamp = SystemTime::now()
             .duration_since(UNIX_EPOCH)
             .unwrap()
             .as_secs()
             .to_string();
         
         Ok(PaytmRequestHeader {
             client_id: auth.client_id.clone(),        // None
             version: "v2".to_string(),                // As specified
             request_timestamp: timestamp,
             channel_id: auth.channel_id.clone(),      // "WEB"
             signature,
         })
     }

     ---
     PHASE 4: CREATE SESSION TOKEN FLOW (PAYTM INITIATE)

     Step 4.1: Define Session Token Request Structure

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Structure for Paytm's initiate transaction API
     How:
     #[derive(Debug, Serialize)]
     pub struct PaytmInitiateTxnRequest {
         pub head: PaytmRequestHeader,
         pub body: PaytmInitiateReqBody,
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmRequestHeader {
         #[serde(rename = "clientId")]
         pub client_id: Option<String>,           // None
         pub version: String,                     // "v2"
         #[serde(rename = "requestTimestamp")]
         pub request_timestamp: String,
         #[serde(rename = "channelId")]
         pub channel_id: String,                  // "WEB"
         pub signature: String,
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmInitiateReqBody {
         #[serde(rename = "requestType")]
         pub request_type: String,                // "Payment"
         pub mid: String,                         // Merchant ID
         #[serde(rename = "orderId")]
         pub order_id: String,                    // Payment ID
         #[serde(rename = "websiteName")]
         pub website_name: String,                // From api_secret
         #[serde(rename = "txnAmount")]
         pub txn_amount: PaytmAmount,
         #[serde(rename = "userInfo")]
         pub user_info: PaytmUserInfo,
         #[serde(rename = "enablePaymentMode")]
         pub enable_payment_mode: Vec<PaytmEnableMethod>,
         #[serde(rename = "callbackUrl")]
         pub callback_url: String,
         // Additional optional fields as needed from Paytm analysis doc
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmAmount {
         pub value: String,    // Decimal amount (e.g., "10.50")
         pub currency: String, // "INR"
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmUserInfo {
         #[serde(rename = "custId")]
         pub cust_id: String,
         pub mobile: Option<String>,
         pub email: Option<String>,
         #[serde(rename = "firstName")]
         pub first_name: Option<String>,
         #[serde(rename = "lastName")]
         pub last_name: Option<String>,
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmEnableMethod {
         pub mode: String,                        // "UPI"
         pub channels: Option<Vec<String>>,       // ["UPIPUSH"] for Intent/Collect
     }

     Step 4.2: Implement CreateSessionToken Flow

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Manual implementation of CreateSessionToken flow
     How:
     impl ConnectorIntegrationV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Paytm {
         fn get_url(
             &self,
             req: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
             connectors: &Connectors,
         ) -> CustomResult<String, errors::ConnectorError> {
             let base_url = self.base_url(connectors);
             let auth = PaytmAuthType::try_from(&req.connector_auth_type)?;
             let merchant_id = auth.merchant_id.peek();
             let order_id = &req.payment_id;
             
             Ok(format!(
                 "{}/theia/api/v1/initiateTransaction?mid={}&orderId={}",
                 base_url, merchant_id, order_id
             ))
         }

         fn get_request_body(
             &self,
             req: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
             connectors: &Connectors,
         ) -> CustomResult<RequestContent, errors::ConnectorError> {
             let request = PaytmInitiateTxnRequest::try_from(req)?;
             Ok(RequestContent::Json(Box::new(request)))
         }

         fn handle_response(
             &self,
             data: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>,
             event_builder: Option<&mut ConnectorEvent>,
             res: Response,
         ) -> CustomResult<RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, errors::ConnectorError> {
             let response: PaytmInitiateTxnResponse = res.response.parse_struct("PaytmInitiateTxnResponse")?;
             
             match response.body {
                 PaytmResBodyTypes::SuccessBody(success_body) => {
                     if success_body.result_info.result_code == "0000" {
                         let mut router_data = data.clone();
                         
                         // Store txnToken in session_token field for Authorize flow
                         router_data.session_token = Some(success_body.txn_token.clone());
                         
                         router_data.response = Ok(PaymentsResponseData::SessionTokenResponse {
                             session_token: success_body.txn_token,
                         });
                         
                         router_data.status = enums::AttemptStatus::AuthenticationPending;
                         Ok(router_data)
                     } else if success_body.result_info.result_code == "0002" {
                         // Duplicate request handling
                         let mut router_data = data.clone();
                         router_data.status = enums::AttemptStatus::Pending;
                         Ok(router_data)
                     } else {
                         Err(errors::ConnectorError::ResponseHandlingFailed.into())
                     }
                 },
                 PaytmResBodyTypes::FailureBody(_) => {
                     Err(errors::ConnectorError::ResponseHandlingFailed.into())
                 }
             }
         }
     }

     Step 4.3: Implement Session Token Request Transformation

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Convert RouterDataV2 to Paytm initiate request
     How:
     impl TryFrom<&RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>> 
         for PaytmInitiateTxnRequest {
         type Error = error_stack::Report<errors::ConnectorError>;
         
         fn try_from(item: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>) -> Result<Self, Self::Error> {
             let auth = PaytmAuthType::try_from(&item.connector_auth_type)?;
             let connector = Paytm::new();
             
             // Convert amount using connector's amount converter
             let amount = connector
                 .amount_converter
                 .convert(item.request.amount, item.request.currency)
                 .change_context(errors::ConnectorError::AmountConversionFailed)?;
             
             // Build request body
             let body = PaytmInitiateReqBody {
                 request_type: "Payment".to_string(),
                 mid: auth.merchant_id.peek().clone(),
                 order_id: item.payment_id.clone(),
                 website_name: auth.website.peek().clone(),
                 txn_amount: PaytmAmount {
                     value: amount,
                     currency: item.request.currency.to_string(),
                 },
                 user_info: PaytmUserInfo {
                     cust_id: item.request.customer_id.as_ref()
                         .map(|id| id.get_string_repr().to_string())
                         .unwrap_or_else(|| "guest".to_string()),
                     mobile: None, // Extract from customer details if available
                     email: None,  // Extract from customer details if available
                     first_name: None,
                     last_name: None,
                 },
                 enable_payment_mode: vec![PaytmEnableMethod {
                     mode: "UPI".to_string(),
                     channels: Some(vec!["UPIPUSH".to_string()]),
                 }],
                 callback_url: item.request.router_return_url.clone()
                     .unwrap_or_else(|| "https://default-callback.com".to_string()),
             };
             
             // Generate header with signature
             let head = create_paytm_header(&body, &auth)?;
             
             Ok(Self { head, body })
         }
     }

     Step 4.4: Define Session Token Response Structure

     File: Same as above
     What: Handle Paytm initiate response
     How:
     #[derive(Debug, Deserialize)]
     pub struct PaytmInitiateTxnResponse {
         pub head: PaytmRespHead,
         pub body: PaytmResBodyTypes,
     }

     #[derive(Debug, Deserialize)]
     #[serde(untagged)]
     pub enum PaytmResBodyTypes {
         SuccessBody(PaytmRespBody),
         FailureBody(PaytmErrorBody),
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmRespBody {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
         #[serde(rename = "txnToken")]
         pub txn_token: String,  // This will be stored as session_token
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmResultInfo {
         #[serde(rename = "resultStatus")]
         pub result_status: String,
         #[serde(rename = "resultCode")]
         pub result_code: String,  // "0000" for success, "0002" for duplicate
         #[serde(rename = "resultMsg")]
         pub result_msg: String,
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmRespHead {
         #[serde(rename = "responseTimestamp")]
         pub response_timestamp: Option<String>,
         pub version: String,
         #[serde(rename = "clientId")]
         pub client_id: Option<String>,
         pub signature: Option<String>,
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmErrorBody {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
     }

     ---
     PHASE 5: AUTHORIZE FLOW (PAYTM PROCESS) - INTENT & COLLECT ROUTING

     Step 5.1: Define UPI Flow Detection

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Detect UPI flow type from payment method data
     How:
     #[derive(Debug, Clone)]
     pub enum UpiFlowType {
         Intent,
         Collect,
     }

     pub fn determine_upi_flow(
         payment_method_data: &PaymentMethodData
     ) -> CustomResult<UpiFlowType, errors::ConnectorError> {
         match payment_method_data {
             PaymentMethodData::Upi(upi_data) => {
                 match upi_data {
                     UpiData::UpiCollect(collect_data) => {
                         // If VPA is provided, it's a collect flow
                         if collect_data.vpa_id.is_some() {
                             Ok(UpiFlowType::Collect)
                         } else {
                             // If no VPA provided, default to Intent
                             Ok(UpiFlowType::Intent)
                         }
                     },
                     UpiData::UpiIntent(_) => {
                         Ok(UpiFlowType::Intent)
                     }
                 }
             },
             _ => {
                 // Default to Intent for non-UPI specific payment methods
                 Ok(UpiFlowType::Intent)
             }
         }
     }

     Step 5.2: Implement Authorize Flow with UPI Routing

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Handle the process transaction step with UPI flow detection
     How:
     impl ConnectorIntegrationV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Paytm {
         fn get_url(
             &self,
             req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
             connectors: &Connectors,
         ) -> CustomResult<String, errors::ConnectorError> {
             let base_url = self.base_url(connectors);
             let auth = PaytmAuthType::try_from(&req.connector_auth_type)?;
             let merchant_id = auth.merchant_id.peek();
             let order_id = &req.payment_id;
             
             // Both Intent and Collect use the same processTransaction endpoint
             Ok(format!(
                 "{}/theia/api/v1/processTransaction?mid={}&orderId={}",
                 base_url, merchant_id, order_id
             ))
         }

         fn get_request_body(
             &self,
             req: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
             connectors: &Connectors,
         ) -> CustomResult<RequestContent, errors::ConnectorError> {
             let flow_type = determine_upi_flow(&req.request.payment_method_data)?;
             
             match flow_type {
                 UpiFlowType::Intent => {
                     let request = PaytmProcessTxnRequest::try_from(req)?;
                     Ok(RequestContent::Json(Box::new(request)))
                 },
                 UpiFlowType::Collect => {
                     let request = PaytmNativeProcessTxnRequest::try_from(req)?;
                     Ok(RequestContent::Json(Box::new(request)))
                 }
             }
         }

         fn handle_response(
             &self,
             data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
             event_builder: Option<&mut ConnectorEvent>,
             res: Response,
         ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
             let flow_type = determine_upi_flow(&data.request.payment_method_data)?;
             
             match flow_type {
                 UpiFlowType::Intent => {
                     let response: PaytmProcessTxnResponse = res.response.parse_struct("PaytmProcessTxnResponse")?;
                     self.handle_intent_response(data, response)
                 },
                 UpiFlowType::Collect => {
                     let response: PaytmNativeProcessTxnResponse = res.response.parse_struct("PaytmNativeProcessTxnResponse")?;
                     self.handle_collect_response(data, response)
                 }
             }
         }
     }

     Step 5.3: Define Authorize Request Structures

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Create structures for Intent and Collect flows
     How:
     // UPI Intent Process Request
     #[derive(Debug, Serialize)]
     pub struct PaytmProcessTxnRequest {
         pub head: PaytmProcessHeadTypes,
         pub body: PaytmProcessBodyTypes,
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmProcessHeadTypes {
         pub version: String,                     // "v2"
         #[serde(rename = "requestTimestamp")]
         pub request_timestamp: String,
         #[serde(rename = "channelId")]
         pub channel_id: String,                  // "WEB"
         #[serde(rename = "txnToken")]
         pub txn_token: String,                   // From CreateSessionToken
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmProcessBodyTypes {
         pub mid: String,
         #[serde(rename = "orderId")]
         pub order_id: String,
         #[serde(rename = "requestType")]
         pub request_type: String,                // "Payment"
         #[serde(rename = "paymentMode")]
         pub payment_mode: String,                // "UPI"
         #[serde(rename = "paymentFlow")]
         pub payment_flow: Option<String>,        // "NONE"
     }

     // UPI Collect Native Process Request
     #[derive(Debug, Serialize)]
     pub struct PaytmNativeProcessTxnRequest {
         pub head: PaytmTxnTokenType,
         pub body: PaytmNativeProcessRequestBody,
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmTxnTokenType {
         #[serde(rename = "txnToken")]
         pub txn_token: String,                   // From CreateSessionToken
     }

     #[derive(Debug, Serialize)]
     pub struct PaytmNativeProcessRequestBody {
         #[serde(rename = "requestType")]
         pub request_type: String,                // "NATIVE"
         pub mid: String,
         #[serde(rename = "orderId")]
         pub order_id: String,
         #[serde(rename = "paymentMode")]
         pub payment_mode: String,                // "UPI"
         #[serde(rename = "payerAccount")]
         pub payer_account: Option<String>,       // UPI VPA for collect
         #[serde(rename = "channelCode")]
         pub channel_code: Option<String>,        // Gateway code
         #[serde(rename = "channelId")]
         pub channel_id: String,                  // "WEB"
         #[serde(rename = "txnToken")]
         pub txn_token: String,                   // From CreateSessionToken
         #[serde(rename = "authMode")]
         pub auth_mode: Option<String>,           // "DEBIT_PIN"
     }

     Step 5.4: Implement Request Transformations

     File: Same as above
     What: Convert RouterDataV2 to appropriate request type
     How:
     // UPI Intent Process Request
     impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> 
         for PaytmProcessTxnRequest {
         type Error = error_stack::Report<errors::ConnectorError>;
         
         fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> Result<Self, Self::Error> {
             let auth = PaytmAuthType::try_from(&item.connector_auth_type)?;
             
             // Get txnToken from session_token (stored by CreateSessionToken flow)
             let txn_token = item.session_token.as_ref()
                 .ok_or(errors::ConnectorError::MissingRequiredField {
                     field_name: "session_token",
                 })?
                 .clone();
             
             let timestamp = SystemTime::now()
                 .duration_since(UNIX_EPOCH)
                 .unwrap()
                 .as_secs()
                 .to_string();
             
             Ok(Self {
                 head: PaytmProcessHeadTypes {
                     version: "v2".to_string(),
                     request_timestamp: timestamp,
                     channel_id: auth.channel_id.clone(),
                     txn_token: txn_token.clone(),
                 },
                 body: PaytmProcessBodyTypes {
                     mid: auth.merchant_id.peek().clone(),
                     order_id: item.payment_id.clone(),
                     request_type: "Payment".to_string(),
                     payment_mode: "UPI".to_string(),
                     payment_flow: Some("NONE".to_string()),
                 },
             })
         }
     }

     // UPI Collect Native Process Request
     impl TryFrom<&RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>> 
         for PaytmNativeProcessTxnRequest {
         type Error = error_stack::Report<errors::ConnectorError>;
         
         fn try_from(item: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>) -> Result<Self, Self::Error> {
             let auth = PaytmAuthType::try_from(&item.connector_auth_type)?;
             
             // Get txnToken from session_token
             let txn_token = item.session_token.as_ref()
                 .ok_or(errors::ConnectorError::MissingRequiredField {
                     field_name: "session_token",
                 })?
                 .clone();
             
             // Extract UPI VPA from payment method data
             let payer_account = extract_upi_vpa(&item.request.payment_method_data)?;
             
             Ok(Self {
                 head: PaytmTxnTokenType { txn_token: txn_token.clone() },
                 body: PaytmNativeProcessRequestBody {
                     request_type: "NATIVE".to_string(),
                     mid: auth.merchant_id.peek().clone(),
                     order_id: item.payment_id.clone(),
                     payment_mode: "UPI".to_string(),
                     payer_account,
                     channel_code: Some("UPI".to_string()),
                     channel_id: auth.channel_id.clone(),
                     txn_token,
                     auth_mode: Some("DEBIT_PIN".to_string()),
                 },
             })
         }
     }

     // Helper function for UPI VPA extraction
     fn extract_upi_vpa(payment_method_data: &PaymentMethodData) -> CustomResult<Option<String>, errors::ConnectorError> {
         match payment_method_data {
             PaymentMethodData::Upi(UpiData::UpiCollect(collect_data)) => {
                 if let Some(vpa_id) = &collect_data.vpa_id {
                     let vpa = vpa_id.peek().to_string();
                     if vpa.contains('@') && vpa.len() > 3 {
                         Ok(Some(vpa))
                     } else {
                         Err(errors::ConnectorError::InvalidRequestData {
                             message: "Invalid UPI VPA format".to_string(),
                         }.into())
                     }
                 } else {
                     Err(errors::ConnectorError::MissingRequiredField {
                         field_name: "vpa_id",
                     }.into())
                 }
             },
             _ => Ok(None),
         }
     }

     ---
     PHASE 6: RESPONSE HANDLING FOR INTENT & COLLECT FLOWS

     Step 6.1: Define Response Structures

     File: backend/connector-integration/src/connectors/paytm/transformers.rs
     What: Handle responses for Intent and Collect flows
     How:
     // UPI Intent Process Response
     #[derive(Debug, Deserialize)]
     pub struct PaytmProcessTxnResponse {
         pub head: PaytmProcessHead,
         pub body: PaytmProcessBodyTypes,
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmProcessHead {
         pub version: Option<String>,
         #[serde(rename = "responseTimestamp")]
         pub response_timestamp: String,
     }

     #[derive(Debug, Deserialize)]
     #[serde(untagged)]
     pub enum PaytmProcessBodyTypes {
         SuccessBody(PaytmProcessSuccessResp),
         FailureBody(PaytmProcessFailureResp),
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmProcessSuccessResp {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
         #[serde(rename = "deepLinkInfo")]
         pub deep_link_info: PaytmDeepLinkInfo,
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmDeepLinkInfo {
         #[serde(rename = "deepLink")]
         pub deep_link: String,                   // UPI intent URL
         #[serde(rename = "orderId")]
         pub order_id: String,
         #[serde(rename = "cashierRequestId")]
         pub cashier_request_id: String,
         #[serde(rename = "transId")]
         pub trans_id: String,
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmProcessFailureResp {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
     }

     // UPI Collect Native Process Response
     #[derive(Debug, Deserialize)]
     pub struct PaytmNativeProcessTxnResponse {
         pub head: PaytmProcessHead,
         pub body: PaytmNativeProcessBodyTypes,
     }

     #[derive(Debug, Deserialize)]
     #[serde(untagged)]
     pub enum PaytmNativeProcessBodyTypes {
         SuccessBody(PaytmNativeProcessSuccessResp),
         FailureBody(PaytmNativeProcessFailureResp),
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmNativeProcessSuccessResp {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
         #[serde(rename = "transId")]
         pub trans_id: String,
         #[serde(rename = "orderId")]
         pub order_id: String,
         // No deepLinkInfo for collect - it's a background process
     }

     #[derive(Debug, Deserialize)]
     pub struct PaytmNativeProcessFailureResp {
         #[serde(rename = "resultInfo")]
         pub result_info: PaytmResultInfo,
     }

     Step 6.2: Implement Response Handlers

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Handle responses for each UPI flow type
     How:
     impl Paytm {
         fn handle_intent_response(
             &self,
             data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
             response: PaytmProcessTxnResponse,
         ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
             match response.body {
                 PaytmProcessBodyTypes::SuccessBody(success_body) => {
                     if success_body.result_info.result_code == "0000" {
                         let mut router_data = data.clone();
                         
                         // Create redirection data with UPI intent link
                         let redirect_form = RedirectForm::Uri {
                             uri: success_body.deep_link_info.deep_link,
                         };
                         
                         router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                             resource_id: ResponseId::ConnectorTransactionId(success_body.deep_link_info.trans_id),
                             redirection_data: Some(redirect_form),
                             mandate_reference: None,
                             connector_metadata: None,
                             network_transaction_id: None,
                             connector_response_reference_id: Some(success_body.deep_link_info.cashier_request_id),
                             incremental_authorization_allowed: None,
                             charge_id: None,
                             integrity_object: Some(AuthoriseIntegrityObject {
                                 amount: router_data.request.amount,
                                 currency: router_data.request.currency,
                             }),
                         });
                         router_data.status = enums::AttemptStatus::AuthenticationPending;
                         Ok(router_data)
                     } else {
                         Err(errors::ConnectorError::ResponseHandlingFailed.into())
                     }
                 },
                 PaytmProcessBodyTypes::FailureBody(_) => {
                     Err(errors::ConnectorError::ResponseHandlingFailed.into())
                 }
             }
         }

         fn handle_collect_response(
             &self,
             data: &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>,
             response: PaytmNativeProcessTxnResponse,
         ) -> CustomResult<RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData>, errors::ConnectorError> {
             match response.body {
                 PaytmNativeProcessBodyTypes::SuccessBody(success_body) => {
                     if success_body.result_info.result_code == "0000" {
                         let mut router_data = data.clone();
                         
                         router_data.response = Ok(PaymentsResponseData::TransactionResponse {
                             resource_id: ResponseId::ConnectorTransactionId(success_body.trans_id),
                             redirection_data: None, // No redirection for collect
                             mandate_reference: None,
                             connector_metadata: None,
                             network_transaction_id: None,
                             connector_response_reference_id: Some(success_body.order_id),
                             incremental_authorization_allowed: None,
                             charge_id: None,
                             integrity_object: Some(AuthoriseIntegrityObject {
                                 amount: router_data.request.amount,
                                 currency: router_data.request.currency,
                             }),
                         });
                         router_data.status = enums::AttemptStatus::Pending; // Collect is async
                         Ok(router_data)
                     } else {
                         Err(errors::ConnectorError::ResponseHandlingFailed.into())
                     }
                 },
                 PaytmNativeProcessBodyTypes::FailureBody(_) => {
                     Err(errors::ConnectorError::ResponseHandlingFailed.into())
                 }
             }
         }
     }

     ---
     PHASE 7: FRAMEWORK INTEGRATION

     Step 7.1: AmountConvertor Integration

     What: Ensure proper amount handling throughout
     How:
     1. All request transformations use: connector.amount_converter.convert(amount, currency)
     2. All response processing uses: connector.amount_converter.convert_back(response_amount, currency)
     3. Test with INR currency specifically for Paytm

     Step 7.2: Integrity Framework Implementation

     File: backend/domain_types/src/types.rs and transformers
     What: Replace integrity object stubs with real implementations
     How:
     1. In domain types: Find and replace all integrity_object: None with:
     integrity_object: Some(AuthoriseIntegrityObject {
         amount: value.minor_amount,
         currency: value.currency,
     })
     2. In transformers: Implement GetIntegrityObject trait:
     impl GetIntegrityObject<AuthoriseIntegrityObject> for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> {
         fn get_response_integrity_object(&self) -> Option<AuthoriseIntegrityObject> {
             match &self.response {
                 Ok(PaymentsResponseData::TransactionResponse { amount, currency, .. }) => {
                     Some(AuthoriseIntegrityObject {
                         amount: *amount,
                         currency: *currency,
                     })
                 }
                 _ => None,
             }
         }

         fn get_request_integrity_object(&self) -> AuthoriseIntegrityObject {
             self.request.integrity_object.clone().unwrap_or_else(|| {
                 AuthoriseIntegrityObject {
                     amount: self.request.amount,
                     currency: self.request.currency,
                 }
             })
         }
     }

     Step 7.3: Source Verification Framework (Initial Stubs)

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Add stub implementations for compilation
     How:
     // Initial stub implementations (will be replaced in final phase)
     impl interfaces::verification::SourceVerification<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Paytm {
         fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
             Ok(Vec::new()) // Stub
         }
         
         fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
             Ok(Box::new(crypto::NoAlgorithm)) // Stub
         }
         
         fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
             Ok(Vec::new()) // Stub
         }
         
         fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
             Ok(payload.to_owned()) // Stub
         }
     }

     impl interfaces::verification::SourceVerification<Authorize, PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData> for Paytm {
         // Similar stub implementations
     }

     // Add stubs for all other flows (PSync, Capture, Void, Refund, etc.)
     macro_rules! impl_source_verification_stub {
         ($flow:ty, $common_data:ty, $req:ty, $resp:ty) => {
             impl interfaces::verification::SourceVerification<$flow, $common_data, $req, $resp> for Paytm {
                 fn get_secrets(&self, _secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
                     Ok(Vec::new()) // Stub
                 }
                 fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
                     Ok(Box::new(crypto::NoAlgorithm)) // Stub
                 }
                 fn get_signature(&self, _payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
                     Ok(Vec::new()) // Stub
                 }
                 fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<$flow, $common_data, $req, $resp>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
                     Ok(payload.to_owned()) // Stub
                 }
             }
         };
     }

     // Apply stub implementations to all flows
     impl_source_verification_stub!(PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData);
     impl_source_verification_stub!(Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData);
     impl_source_verification_stub!(Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData);
     impl_source_verification_stub!(Refund, RefundFlowData, RefundsData, RefundsResponseData);
     impl_source_verification_stub!(RSync, RefundFlowData, RefundSyncData, RefundsResponseData);

     ---
     PHASE 8: ADDITIONAL FLOW IMPLEMENTATIONS

     Step 8.1: Payment Sync Implementation

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Implement payment status checking
     How:
     impl ConnectorIntegrationV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData> for Paytm {
         fn get_url(&self, req: &RouterDataV2<PSync, ...>, connectors: &Connectors) -> CustomResult<String, errors::ConnectorError> {
             let base_url = self.base_url(connectors);
             let auth = PaytmAuthType::try_from(&req.connector_auth_type)?;
             let merchant_id = auth.merchant_id.peek();
             
             // Extract payment ID from connector_transaction_id
             let payment_id = match &req.request.connector_transaction_id {
                 ResponseId::ConnectorTransactionId(id) => id,
                 ResponseId::EncodedData(data) => data,
                 ResponseId::NoResponseId => {
                     return Err(errors::ConnectorError::MissingRequiredField {
                         field_name: "connector_transaction_id",
                     }.into());
                 }
             };
             
             Ok(format!("{}/merchant-status/api/v1/getPaymentStatus?mid={}&orderId={}", 
                       base_url, merchant_id, payment_id))
         }

         fn get_request_body(&self, req: &RouterDataV2<PSync, ...>, connectors: &Connectors) -> CustomResult<RequestContent, errors::ConnectorError> {
             // Paytm status API might use GET or require specific request body
             Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
         }

         fn handle_response(&self, data: &RouterDataV2<PSync, ...>, event_builder: Option<&mut ConnectorEvent>, res: Response) -> CustomResult<RouterDataV2<PSync, ...>, errors::ConnectorError> {
             // Parse Paytm status response and map to payment status
             let response: PaytmStatusResponse = res.response.parse_struct("PaytmStatusResponse")?;
             // Implementation for status mapping
             todo!("Implement status response mapping")
         }
     }

     Step 8.2: Stub Other Required Flows

     File: Same as above
     What: Add stub implementations for other flows
     How:
     // Capture (stub for future implementation)
     impl ConnectorIntegrationV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData> for Paytm {}

     // Void (stub for future implementation)
     impl ConnectorIntegrationV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData> for Paytm {}

     // Refund (stub for future implementation)
     impl ConnectorIntegrationV2<Refund, RefundFlowData, RefundsData, RefundsResponseData> for Paytm {}

     // Refund Sync (stub for future implementation)
     impl ConnectorIntegrationV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData> for Paytm {}

     // Setup Mandate (stub for future implementation)
     impl ConnectorIntegrationV2<SetupMandate, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Paytm {}

     // Dispute flows (stubs for future implementation)
     impl ConnectorIntegrationV2<Accept, DisputeFlowData, AcceptDisputeData, DisputeResponseData> for Paytm {}
     impl ConnectorIntegrationV2<SubmitEvidence, DisputeFlowData, SubmitEvidenceData, DisputeResponseData> for Paytm {}
     impl ConnectorIntegrationV2<DefendDispute, DisputeFlowData, DisputeDefendData, DisputeResponseData> for Paytm {}

     // Incoming webhook (stub for future implementation)
     impl ConnectorIntegrationV2<IncomingWebhook, PaymentFlowData, IncomingWebhookRequestDetails, PaymentsResponseData> for Paytm {}

     ---
     PHASE 9: SOURCE VERIFICATION COMPLETION

     Step 9.1: Replace Stub Implementations with Real Logic

     File: backend/connector-integration/src/connectors/paytm.rs
     What: Implement actual source verification logic
     How:
     impl interfaces::verification::SourceVerification<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData> for Paytm {
         fn get_secrets(&self, secrets: ConnectorSourceVerificationSecrets) -> CustomResult<Vec<u8>, ConnectorError> {
             match secrets {
                 ConnectorSourceVerificationSecrets::AuthHeaders(ConnectorAuthType::SignatureKey { key1, .. }) => {
                     Ok(key1.peek().as_bytes().to_vec())
                 }
                 _ => Err(ConnectorError::InvalidConnectorConfig {
                     config: "Unsupported secret type for Paytm".to_string(),
                 }.into())
             }
         }
         
         fn get_algorithm(&self) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
             Ok(Box::new(crypto::HmacSha256))
         }
         
         fn get_signature(&self, payload: &[u8], router_data: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
             // Implement Paytm-specific signature verification
             let expected_signature = self.calculate_expected_signature(payload, secrets)?;
             Ok(expected_signature)
         }
         
         fn get_message(&self, payload: &[u8], _router_data: &RouterDataV2<CreateSessionToken, PaymentFlowData, SetupMandateRequestData, PaymentsResponseData>, _secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
             Ok(payload.to_owned())
         }
     }

     // Similar implementations for Authorize and other flows

     impl Paytm {
         fn calculate_expected_signature(&self, payload: &[u8], secrets: &[u8]) -> CustomResult<Vec<u8>, ConnectorError> {
             use crypto::sha2::{Sha256, Digest};
             use crypto::hmac::{Hmac, Mac};
             
             type HmacSha256 = Hmac<Sha256>;
             
             let mut mac = HmacSha256::new_from_slice(secrets)
                 .map_err(|_| ConnectorError::InvalidConnectorConfig {
                     config: "Invalid secret for HMAC calculation".to_string(),
                 })?;
             
             mac.update(payload);
             Ok(mac.finalize().into_bytes().to_vec())
         }
     }

     ---
     FINAL COMPILATION & VALIDATION

     Step 10.1: Comprehensive Compilation Check

     Commands to run:
     cargo build                                    # Basic compilation
     cargo +nightly fmt --all                      # Formatting
     cargo hack clippy --each-feature --no-dev-deps # Linting

     Step 10.2: Flow Validation

     What: Test UPI Intent and Collect flow combinations
     How:
     1. UPI Intent: CreateSessionToken → Authorize (with txnToken and deep link generation)
     2. UPI Collect: CreateSessionToken → Authorize (with txnToken and VPA processing)
     3. Verify framework integration (amount conversion, integrity, source verification)

     Step 10.3: Integration Validation

     What: Ensure multi-flow orchestration works
     How:
     1. Test that should_do_session_token() returns true triggers CreateSessionToken
     2. Test that session_token is properly passed to Authorize step
     3. Test that Intent/Collect flows route to correct request structures
     4. Verify error handling and status mapping for all flows

     ---
     FUTURE IMPLEMENTATION (TODO)

     QR Flow Implementation (Phase 11 - Future)

     When to implement: After Intent and Collect flows are stable
     Requirements:
     1. Add UpiFlowType::QR to flow detection
     2. Implement QR-specific request/response structures
     3. Add QR endpoint (/paymentservices/qr/create)
     4. Handle QR-specific signature generation (bypass session token)
     5. Process QR response with image data

     Additional Features (Phase 12+ - Future)

     1. Payment Capture: If Paytm supports capture operations
     2. Payment Void: If Paytm supports void operations  
     3. Refund Operations: Full refund flow implementation
     4. Webhook Handling: Incoming webhook processing
     5. Dispute Management: Dispute handling flows

     ---
     Key Benefits of This Intent & Collect Implementation

     1. Framework Compliance: Uses proper multi-flow architecture (CreateSessionToken → Authorize)
     2. Clean Separation: Session token creation separate from payment processing
     3. UPI Flow Routing: Clear distinction between Intent (deep link) and Collect (VPA) flows
     4. Authentication Simplification: Uses SignatureKey with clear field mapping
     5. Extensibility: Easy to add QR flow later without major architectural changes
     6. Framework Integration: Proper integration with amount conversion, integrity, and source verification
     7. Error Handling: Comprehensive error mapping and status handling
     8. Security: Proper signature generation and verification according to Paytm specifications

     This plan provides a solid foundation for implementing Paytm's UPI Intent and Collect flows, with clear architecture for adding QR functionality later.