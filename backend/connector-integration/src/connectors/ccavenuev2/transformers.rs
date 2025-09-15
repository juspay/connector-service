use common_utils::errors::CustomResult;
use domain_types::{
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsResponseData, PaymentsSyncData,
    },
    errors,
    payment_address::PaymentAddress,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes, UpiData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,

    utils::ForeignTryFrom,
};
use hyperswitch_masking::{ExposeInterface, Mask, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

// Request types for CCAvenue V2 API
#[derive(Debug, Serialize, Clone)]
pub struct CcavenueV2PaymentsRequest {
    pub merchant_id: String,
    pub access_code: String,
    pub order_id: String,
    pub currency: String,
    pub amount: String,
    pub redirect_url: String,
    pub cancel_url: String,
    pub language: String,
    pub billing_name: Option<String>,
    pub billing_address: Option<String>,
    pub billing_city: Option<String>,
    pub billing_state: Option<String>,
    pub billing_country: Option<String>,
    pub billing_tel: Option<String>,
    pub billing_email: Option<String>,
    pub delivery_name: Option<String>,
    pub delivery_address: Option<String>,
    pub delivery_city: Option<String>,
    pub delivery_state: Option<String>,
    pub delivery_country: Option<String>,
    pub delivery_tel: Option<String>,
    pub merchant_param1: Option<String>,
    pub merchant_param2: Option<String>,
    pub merchant_param3: Option<String>,
    pub merchant_param4: Option<String>,
    pub merchant_param5: Option<String>,
    pub integration_type: String,
    pub promocode: Option<String>,
    pub customer_identifier: Option<String>,
    pub payment_option: String,
    pub vpa: Option<String>, // For UPI payments
}

#[derive(Debug, Serialize, Clone)]
pub struct CcavenueV2PaymentsSyncRequest {
    pub reference_no: String,
    pub order_no: String,
}

// Response types for CCAvenue V2 API
#[derive(Debug, Deserialize, Clone)]
pub struct CcavenueV2PaymentsSuccessResponse {
    pub order_id: String,
    pub tracking_id: String,
    pub bank_ref_no: Option<String>,
    pub order_status: String,
    pub failure_message: Option<String>,
    pub payment_mode: String,
    pub card_name: Option<String>,
    pub status_code: String,
    pub status_message: Option<String>,
    pub currency: String,
    pub amount: String,
    pub billing_name: Option<String>,
    pub billing_tel: Option<String>,
    pub billing_email: Option<String>,
    pub trans_date: String,
    pub bin_name: Option<String>,
    pub bin_number: Option<String>,
    pub bank_name: Option<String>,
    pub gateway_name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CcavenueV2ErrorResponse {
    pub order_id: Option<String>,
    pub status_code: String,
    pub status_message: String,
    pub error_code: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub enum CcavenueV2PaymentsResponse {
    Success(CcavenueV2PaymentsSuccessResponse),
    Error(CcavenueV2ErrorResponse),
}

#[derive(Debug, Deserialize, Clone)]
pub struct CcavenueV2PaymentsSyncResponse {
    pub order_id: String,
    pub order_status: String,
    pub amount: String,
    pub currency: String,
    pub tracking_id: Option<String>,
    pub bank_ref_no: Option<String>,
    pub payment_mode: String,
    pub trans_date: String,
    pub status_code: String,
    pub status_message: Option<String>,
}

// Implement ForeignTryFrom trait for request conversions
impl<T> ForeignTryFrom<RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>>
    for CcavenueV2PaymentsRequest
where
    T: PaymentMethodDataTypes + Clone + Send + Sync,
{
    type Error = errors::ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    ) -> CustomResult<Self, Self::Error> {
        let auth = match item.connector_auth_type {
            ConnectorAuthType::SignatureKey {
                api_key: merchant_id,
                key1: access_code,
                api_secret: working_key,
            } => (merchant_id, access_code, working_key),
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_auth_type",
                }
                .into())
            }
        };

        let vpa = match &item.request.payment_method_data {
            PaymentMethodData::Upi(upi_data) => match upi_data {
                UpiData::UpiCollect(collect_data) => collect_data.vpa_id.as_ref(),
                UpiData::UpiIntent(_) => None,
            },
            _ => None,
        };
        
        let vpa_str = vpa.ok_or_else(|| errors::ConnectorError::MissingRequiredField {
            field_name: "upi.vpa",
        })?;

        Ok(Self {
            merchant_id: auth.0.expose(),
            access_code: auth.1.expose(),
            order_id: item.resource_common_data.payment_id.clone(),
            currency: item.request.currency.to_string(),
            amount: item.request.minor_amount.to_string(),
            redirect_url: item.request.router_return_url.clone().unwrap_or_default(),
            cancel_url: item.request.router_return_url.clone().unwrap_or_default(),
            language: "EN".to_string(),
            billing_name: item.resource_common_data.get_optional_billing_first_name().map(|f| f.expose()),
            billing_address: item.resource_common_data.get_optional_billing_line1().map(|l| l.expose()),
            billing_city: item.resource_common_data.get_optional_billing_city(),
            billing_state: item.resource_common_data.get_optional_billing_state().map(|s| s.expose()),
            billing_country: item.resource_common_data.get_optional_billing_country().map(|c| c.to_string()),
            billing_tel: item.resource_common_data.get_optional_billing_phone_number().map(|p| p.expose()),
            billing_email: item.request.email.as_ref().map(|e| e.peek().to_string()),
            delivery_name: item.resource_common_data.get_optional_shipping_first_name().map(|f| f.expose()),
            delivery_address: item.resource_common_data.get_optional_shipping_line1().map(|l| l.expose()),
            delivery_city: item.resource_common_data.get_optional_shipping_city(),
            delivery_state: item.resource_common_data.get_optional_shipping_state().map(|s| s.expose()),
            delivery_country: item.resource_common_data.get_optional_shipping_country().map(|c| c.to_string()),
            delivery_tel: item.resource_common_data.get_optional_shipping_phone_number().map(|p| p.expose()),
            merchant_param1: None,
            merchant_param2: None,
            merchant_param3: None,
            merchant_param4: None,
            merchant_param5: None,
            integration_type: "iframe_normal".to_string(),
            promocode: None,
            customer_identifier: None,
            payment_option: "upi".to_string(),
            vpa: Some(vpa_str.clone().expose().to_string()),
        })
    }
}

impl ForeignTryFrom<RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for CcavenueV2PaymentsSyncRequest
{
    type Error = errors::ConnectorError;

    fn foreign_try_from(
        item: RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> CustomResult<Self, Self::Error> {
        let auth = match item.connector_auth_type {
            ConnectorAuthType::SignatureKey {
                api_key: merchant_id,
                key1: access_code,
                api_secret: _working_key,
            } => (merchant_id, access_code),
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_auth_type",
                }
                .into())
            }
        };

        Ok(Self {
            reference_no: auth.0.expose(),
            order_no: item.resource_common_data.payment_id.clone(),
        })
    }
}

// Implement ForeignTryFrom trait for response conversions
impl<T> ForeignTryFrom<CcavenueV2PaymentsResponse>
    for RouterDataV2<domain_types::connector_flow::Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
where
    T: PaymentMethodDataTypes + Clone + Send + Sync,
{
    type Error = errors::ConnectorError;

    fn foreign_try_from(
        item: CcavenueV2PaymentsResponse,
    ) -> CustomResult<Self, Self::Error> {
        match item {
            CcavenueV2PaymentsResponse::Success(success) => {
                let status = match success.order_status.as_str() {
                    "Success" => common_enums::AttemptStatus::Charged,
                    "Pending" => common_enums::AttemptStatus::Pending,
                    "Aborted" => common_enums::AttemptStatus::Failure,
                    "Invalid" => common_enums::AttemptStatus::Failure,
                    _ => common_enums::AttemptStatus::Failure,
                };

                // Clone order_id before using it
                let order_id_clone = success.order_id.clone();
                
                // Create a PaymentsResponseData for success case
                let response_data = PaymentsResponseData::TransactionResponse {
                    resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(success.tracking_id),
                    redirection_data: None,
                    connector_metadata: None,
                    mandate_reference: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    status_code: 200,
                };

                // Create a default PaymentFlowData
                let flow_data = PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: order_id_clone,
                    attempt_id: "default_attempt".to_string(),
                    status,
                    payment_method: common_enums::PaymentMethod::Upi,
                    description: None,
                    return_url: None,
                    address: PaymentAddress::new(None, None, None, Some(false)),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: success.order_id.clone(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connector_response_headers: None,
                    external_latency: None,
                    connectors: domain_types::types::Connectors::default(),
                    raw_connector_response: None,
                };
                
                Ok(RouterDataV2 {
                    flow: std::marker::PhantomData,
                    resource_common_data: flow_data,
                    connector_auth_type: ConnectorAuthType::SignatureKey {
                        api_key: "default_key".to_string().into(),
                        key1: "default_key1".to_string().into(),
                        api_secret: "default_secret".to_string().into(),
                    },
                    request: PaymentsAuthorizeData {
                        payment_method_data: PaymentMethodData::Upi(UpiData::UpiIntent(
                            domain_types::payment_method_data::UpiIntentData {}
                        )),
                        amount: success.amount.parse().unwrap_or(0),
                        order_tax_amount: None,
                        email: None,
                        customer_name: None,
                        currency: common_enums::Currency::INR,
                        confirm: true,
                        statement_descriptor_suffix: None,
                        statement_descriptor: None,
                        capture_method: None,
                        router_return_url: None,
                        webhook_url: None,
                        complete_authorize_url: None,
                        mandate_id: None,
                        setup_future_usage: None,
                        off_session: None,
                        browser_info: None,
                        order_category: None,
                        session_token: None,
                        enrolled_for_3ds: false,
                        related_transaction_id: None,
                        payment_experience: None,
                        payment_method_type: Some(common_enums::PaymentMethodType::UpiIntent),
                        customer_id: None,
                        request_incremental_authorization: false,
                        metadata: None,
                        minor_amount: common_utils::types::MinorUnit::new(success.amount.parse().unwrap_or(0)),
                        merchant_order_reference_id: None,
                        shipping_cost: None,
                        merchant_account_id: None,
                        integrity_object: None,
                        merchant_config_currency: None,
                        all_keys_required: None,
                    },
                    response: Ok(response_data),
                })
            }
            CcavenueV2PaymentsResponse::Error(error) => {
                let error_response = ErrorResponse {
                    status_code: error.status_code.parse().unwrap_or(400),
                    message: if error.status_message.is_empty() { "Unknown error".to_string() } else { error.status_message },
                    code: error.error_code.unwrap_or_else(|| "HE_00".to_string()),
                    reason: None,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: None,
                };
                // Create a minimal PaymentFlowData for error case
                let error_flow_data = PaymentFlowData {
                    merchant_id: common_utils::id_type::MerchantId::default(),
                    customer_id: None,
                    connector_customer: None,
                    payment_id: "error_payment".to_string(),
                    attempt_id: "error_attempt".to_string(),
                    status: common_enums::AttemptStatus::Failure,
                    payment_method: common_enums::PaymentMethod::Upi,
                    description: None,
                    return_url: None,
                    address: PaymentAddress::new(None, None, None, Some(false)),
                    auth_type: common_enums::AuthenticationType::NoThreeDs,
                    connector_meta_data: None,
                    amount_captured: None,
                    minor_amount_captured: None,
                    access_token: None,
                    session_token: None,
                    reference_id: None,
                    payment_method_token: None,
                    preprocessing_id: None,
                    connector_api_version: None,
                    connector_request_reference_id: "error_reference".to_string(),
                    test_mode: None,
                    connector_http_status_code: None,
                    connector_response_headers: None,
                    external_latency: None,
                    connectors: domain_types::types::Connectors::default(),
                    raw_connector_response: None,
                };
                
                // Create a minimal PaymentsAuthorizeData for error case
                let error_request_data = PaymentsAuthorizeData {
                    payment_method_data: PaymentMethodData::Upi(UpiData::UpiIntent(
                        domain_types::payment_method_data::UpiIntentData {}
                    )),
                    amount: 0,
                    order_tax_amount: None,
                    email: None,
                    customer_name: None,
                    currency: common_enums::Currency::INR,
                    confirm: true,
                    statement_descriptor_suffix: None,
                    statement_descriptor: None,
                    capture_method: None,
                    router_return_url: None,
                    webhook_url: None,
                    complete_authorize_url: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    browser_info: None,
                    order_category: None,
                    session_token: None,
                    enrolled_for_3ds: false,
                    related_transaction_id: None,
                    payment_experience: None,
                    payment_method_type: Some(common_enums::PaymentMethodType::UpiIntent),
                    customer_id: None,
                    request_incremental_authorization: false,
                    metadata: None,
                    minor_amount: common_utils::types::MinorUnit::new(0),
                    merchant_order_reference_id: None,
                    shipping_cost: None,
                    merchant_account_id: None,
                    integrity_object: None,
                    merchant_config_currency: None,
                    all_keys_required: None,
                };
                
                Ok(Self {
                    flow: std::marker::PhantomData,
                    resource_common_data: error_flow_data,
                    connector_auth_type: ConnectorAuthType::NoKey,
                    request: error_request_data,
                    response: Err(error_response),
                })
            },
        }
    }
}

impl ForeignTryFrom<CcavenueV2PaymentsSyncResponse>
    for RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = errors::ConnectorError;

    fn foreign_try_from(
        item: CcavenueV2PaymentsSyncResponse,
    ) -> CustomResult<Self, Self::Error> {
        let status = match item.order_status.as_str() {
            "Success" => common_enums::AttemptStatus::Charged,
            "Pending" => common_enums::AttemptStatus::Pending,
            "Aborted" => common_enums::AttemptStatus::Failure,
            "Invalid" => common_enums::AttemptStatus::Failure,
            _ => common_enums::AttemptStatus::Failure,
        };

        // Clone order_id before using it
        let order_id_clone = item.order_id.clone();
        
        // Create a PaymentsResponseData for success case
        let response_data = PaymentsResponseData::TransactionResponse {
            resource_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(order_id_clone),
            redirection_data: None,
            connector_metadata: None,
            mandate_reference: None,
            network_txn_id: item.tracking_id,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: 200,
        };

        // Create a default PaymentFlowData
        let flow_data = PaymentFlowData {
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            payment_id: item.order_id.clone(),
            attempt_id: "default_attempt".to_string(),
            status,
            payment_method: common_enums::PaymentMethod::Upi,
            description: None,
            return_url: None,
            address: PaymentAddress::new(None, None, None, Some(false)),
            auth_type: common_enums::AuthenticationType::NoThreeDs,
            connector_meta_data: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            preprocessing_id: None,
            connector_api_version: None,
            connector_request_reference_id: item.order_id.clone(),
            test_mode: None,
            connector_http_status_code: None,
            connector_response_headers: None,
            external_latency: None,
            connectors: domain_types::types::Connectors::default(),
            raw_connector_response: None,
        };
        
        Ok(RouterDataV2 {
            flow: std::marker::PhantomData,
            resource_common_data: flow_data,
            connector_auth_type: ConnectorAuthType::SignatureKey {
                api_key: "default_key".to_string().into(),
                key1: "default_key1".to_string().into(),
                api_secret: "default_secret".to_string().into(),
            },
            request: PaymentsSyncData {
                connector_transaction_id: domain_types::connector_types::ResponseId::ConnectorTransactionId(item.order_id),
                encoded_data: None,
                capture_method: None,
                connector_meta: None,
                sync_type: domain_types::router_request_types::SyncRequestType::SinglePaymentSync,
                mandate_id: None,
                payment_method_type: Some(common_enums::PaymentMethodType::UpiIntent),
                currency: common_enums::Currency::INR,
                payment_experience: None,
                amount: common_utils::types::MinorUnit::new(item.amount.parse().unwrap_or(0)),
                integrity_object: None,
                all_keys_required: None,
            },
            response: Ok(response_data),
        })
    }
}

// Encryption and decryption functions (placeholder implementations)
pub fn encrypt_request(data: &str, _working_key: &str) -> CustomResult<String, errors::ConnectorError> {
    // TODO: Implement actual AES encryption
    // For now, using base64 as placeholder
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(data))
}

pub fn decrypt_response(data: &str, _working_key: &str) -> CustomResult<String, errors::ConnectorError> {
    // TODO: Implement actual AES decryption
    // For now, using base64 as placeholder
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(data)
        .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
    Ok(String::from_utf8(decoded).map_err(|_| errors::ConnectorError::ResponseDeserializationFailed)?)
}

// Helper function to build authentication headers
pub fn build_auth_headers(
    merchant_id: &Secret<String>,
    access_code: &Secret<String>,
    working_key: &Secret<String>,
) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
    let mut headers = Vec::new();
    headers.push(("merchant_id".to_string(), merchant_id.clone().into_masked()));
    headers.push(("access_code".to_string(), access_code.clone().into_masked()));
    headers.push(("working_key".to_string(), working_key.clone().into_masked()));
    Ok(headers)
}