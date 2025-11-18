use common_utils::types::MinorUnit;
use domain_types::{
    connector_flow::Authorize,
    connector_types::{
        PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData, PaymentsResponseData,
        PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData, RefundsResponseData,
        RepeatPaymentData, ResponseId,
    },
    errors::ConnectorError,
    payment_method_data::{PaymentMethodData, PaymentMethodDataTypes},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_data_v2::RouterDataV2,
};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::ResponseRouterData;

// Authentication Type Definition
#[derive(Debug, Clone)]
pub struct BamboraapacAuthType {
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub account_number: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for BamboraapacAuthType {
    type Error = ConnectorError;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                api_secret,
                key1,
            } => Ok(Self {
                username: api_key.clone(),
                password: api_secret.clone(),
                account_number: key1.clone(),
            }),
            ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                username: api_key.clone(),
                password: key1.clone(),
                account_number: api_key.clone(), // Using api_key as account number if not provided
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType),
        }
    }
}

// Transaction Types for Bambora APAC
#[derive(Debug, Clone, Copy)]
pub enum BamboraapacTrnType {
    Purchase = 1,
    PreAuth = 2,
    Capture = 3,
    Refund = 5,
    DirectDebit = 7,
}

// Request Structure for SOAP/XML
#[derive(Debug, Clone)]
pub struct BamboraapacPaymentRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub account_number: Secret<String>,
    pub cust_number: Option<String>,
    pub cust_ref: String,
    pub amount: MinorUnit,
    pub trn_type: BamboraapacTrnType,
    pub card_number: Secret<String>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub cvn: Secret<String>,
    pub card_holder_name: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    _phantom: std::marker::PhantomData<T>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > BamboraapacPaymentRequest<T>
{

    // Generate SOAP XML request
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:dts="http://www.ippayments.com.au/interface/api/dts">
                <soapenv:Body>
                    <dts:SubmitSinglePayment>
                        <dts:trnXML>
                            <![CDATA[

        <Transaction>
            <CustRef>{}</CustRef>
            <Amount>{}</Amount>
            <TrnType>{}</TrnType>
            <AccountNumber>{}</AccountNumber>

                    <CreditCard Registered="False">
                        <CardNumber>{}</CardNumber>
                        <ExpM>{}</ExpM>
                        <ExpY>{}</ExpY>
                        <CVN>{}</CVN>
                        <CardHolderName>{}</CardHolderName>
                    </CreditCard>

            <Security>
                    <UserName>{}</UserName>
                    <Password>{}</Password>
            </Security>
        </Transaction>

                            ]]>
                        </dts:trnXML>
                    </dts:SubmitSinglePayment>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.cust_ref,
            self.amount.get_amount_as_i64(),
            self.trn_type as i32,
            self.account_number.peek(),
            self.card_number.peek(),
            self.exp_month.peek(),
            self.exp_year.peek(),
            self.cvn.peek(),
            self.card_holder_name.peek(),
            self.username.peek(),
            self.password.peek()
        )
    }
}

// Response Structure - Nested SOAP/XML response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BamboraapacPaymentResponse {
    #[serde(rename = "Body")]
    pub body: BodyResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct BodyResponse {
    pub submit_single_payment_response: SubmitSinglePaymentResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitSinglePaymentResponse {
    pub submit_single_payment_result: SubmitSinglePaymentResult,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitSinglePaymentResult {
    pub response: PaymentResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PaymentResponse {
    pub response_code: u8,
    pub receipt: String,
    pub credit_card_token: Option<String>,
    pub declined_code: Option<String>,
    pub declined_message: Option<String>,
}

// Error Response Structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BamboraapacErrorResponse {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub transaction_id: Option<String>,
}

impl Default for BamboraapacErrorResponse {
    fn default() -> Self {
        Self {
            error_code: Some("UNKNOWN_ERROR".to_string()),
            error_message: Some("Unknown error occurred".to_string()),
            transaction_id: None,
        }
    }
}

// ============================================================================
// CAPTURE FLOW STRUCTURES
// ============================================================================

// Capture Request Structure
#[derive(Debug, Clone)]
pub struct BamboraapacCaptureRequest {
    pub cust_ref: String,
    pub receipt: String,
    pub amount: MinorUnit,
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl BamboraapacCaptureRequest {
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:dts="http://www.ippayments.com.au/interface/api/dts">
                <soapenv:Header/>
                <soapenv:Body>
                    <dts:SubmitSingleRefund>
                        <dts:trnXML>
                            <![CDATA[
                    <Refund>
                        <CustRef>{}</CustRef>
                        <Receipt>{}</Receipt>
                        <Amount>{}</Amount>
                        <Security>
                            <UserName>{}</UserName>
                            <Password>{}</Password>
                        </Security>
                    </Refund>
                ]]>
                        </dts:trnXML>
                    </dts:SubmitSingleRefund>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.cust_ref,
            self.receipt,
            self.amount.get_amount_as_i64(),
            self.username.peek(),
            self.password.peek()
        )
    }
}

// ============================================================================
// REFUND FLOW STRUCTURES
// ============================================================================

// Refund Request Structure
#[derive(Debug, Clone)]
pub struct BamboraapacRefundRequest {
    pub cust_ref: String,
    pub receipt: String, // Original transaction receipt/ID to refund
    pub amount: MinorUnit,
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl BamboraapacRefundRequest {
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:dts="http://www.ippayments.com.au/interface/api/dts">
                <soapenv:Header/>
                <soapenv:Body>
                    <dts:SubmitSingleRefund>
                        <dts:trnXML>
                            <![CDATA[
                    <Refund>
                        <CustRef>{}</CustRef>
                        <Receipt>{}</Receipt>
                        <Amount>{}</Amount>
                        <Security>
                            <UserName>{}</UserName>
                            <Password>{}</Password>
                        </Security>
                    </Refund>
                ]]>
                        </dts:trnXML>
                    </dts:SubmitSingleRefund>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.cust_ref,
            self.receipt,
            self.amount.get_amount_as_i64(),
            self.username.peek(),
            self.password.peek()
        )
    }
}

// Refund Response Structure
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct BamboraapacRefundResponse {
    pub body: RefundBodyResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundBodyResponse {
    #[serde(rename = "SubmitSingleRefundResponse")]
    pub submit_single_refund_response: SubmitSingleRefundResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitSingleRefundResponse {
    pub submit_single_refund_result: String, // HTML-encoded XML string
}

// Inner refund response structure (after decoding HTML entities)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RefundResponseInner {
    pub response_code: u8,
    pub timestamp: Option<String>,
    pub receipt: String,
    pub settlement_date: Option<String>,
    pub declined_code: Option<String>,
    pub declined_message: Option<String>,
}

// ============================================================================
// SYNC FLOW STRUCTURES (PSync and RSync)
// ============================================================================

// Sync Request Structure
#[derive(Debug, Clone)]
pub struct BamboraapacSyncRequest {
    pub account_number: Secret<String>,
    pub receipt: String, // Transaction receipt/ID to query
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl BamboraapacSyncRequest {
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:dts="http://www.ippayments.com.au/interface/api/dts">
                <soapenv:Header/>
                <soapenv:Body>
                    <dts:QueryTransaction>
                        <dts:queryXML>
                            <![CDATA[
                                <QueryTransaction>
                                    <Criteria>
                                        <AccountNumber>{}</AccountNumber>
                                        <TrnStartTimestamp>2024-06-23 00:00:00</TrnStartTimestamp>
                                        <TrnEndTimestamp>2099-12-31 23:59:59</TrnEndTimestamp>
                                        <Receipt>{}</Receipt>
                                    </Criteria>
                                    <Security>
                                        <UserName>{}</UserName>
                                        <Password>{}</Password>
                                    </Security>
                            </QueryTransaction>
                            ]]>
                        </dts:queryXML>
                    </dts:QueryTransaction>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.account_number.peek(),
            self.receipt,
            self.username.peek(),
            self.password.peek()
        )
    }
}

// Sync Response Structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BamboraapacSyncResponse {
    #[serde(rename = "Body")]
    pub body: SyncBodyResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QueryTransactionResponse {
    query_transaction_result: QueryTransactionResult,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncBodyResponse {
    pub query_transaction_response: QueryTransactionResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncResponse {
    response_code: u8,
    receipt: String,
    declined_code: Option<String>,
    declined_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QueryResponse {
    response: Option<SyncResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct QueryTransactionResult {
    query_response: QueryResponse,
}

// Inner payment response structure for successful queries
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InnerPaymentResponse {
    pub response_code: u8,
    pub receipt: String,
    pub credit_card_token: Option<String>,
    pub declined_code: Option<String>,
    pub declined_message: Option<String>,
}

// Request Transformation Implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<(
        MinorUnit,
        &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
    )> for BamboraapacPaymentRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        (amount, router_data): (
            MinorUnit,
            &RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        ),
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract card data
        let card_data = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(ConnectorError::NotImplemented(
                "Payment method not supported".to_string(),
            )),
        }?;

        // Determine transaction type based on capture method
        let trn_type = match router_data.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => BamboraapacTrnType::PreAuth,
            _ => BamboraapacTrnType::Purchase,
        };

        // Convert card number to string by serializing
        let card_number_json = serde_json::to_value(&card_data.card_number.0)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let card_number_str = card_number_json
            .as_str()
            .ok_or(ConnectorError::RequestEncodingFailed)?
            .to_string();

        Ok(Self {
            account_number: auth.account_number,
            cust_number: router_data.request.customer_id.as_ref().map(|id| id.get_string_repr().to_string()),
            cust_ref: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount,
            trn_type,
            card_number: Secret::new(card_number_str),
            exp_month: card_data.card_exp_month.clone(),
            exp_year: card_data.get_expiry_year_4_digit(),
            cvn: card_data.card_cvc.clone(),
            card_holder_name: card_data
                .card_holder_name
                .clone()
                .unwrap_or_else(|| Secret::new("".to_string())),
            username: auth.username,
            password: auth.password,
            _phantom: std::marker::PhantomData,
        })
    }
}


// Response Transformation Implementation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            BamboraapacPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraapacPaymentResponse,
            RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response.body.submit_single_payment_response.submit_single_payment_result.response;
        let router_data = &item.router_data;

        // Map Bambora response code to standard status
        // 0 = Approved, 1 = Not Approved
        let status = if response.response_code == 0 {
            if router_data
                .request
                .capture_method
                == Some(common_enums::CaptureMethod::Manual)
            {
                common_enums::AttemptStatus::Authorized
            } else {
                common_enums::AttemptStatus::Charged
            }
        } else {
            common_enums::AttemptStatus::Failure
        };

        // Handle error responses
        if status == common_enums::AttemptStatus::Failure {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Payment declined".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.receipt.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.receipt.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// CAPTURE FLOW TRANSFORMERS
// ============================================================================

// Capture Request Transformation
impl TryFrom<&RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>>
    for BamboraapacCaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the connector transaction ID (receipt) from the payment attempt
        let receipt = match &router_data.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) | ResponseId::EncodedData(id) => id.clone(),
            ResponseId::NoResponseId => {
                return Err(error_stack::report!(ConnectorError::MissingRequiredField {
                    field_name: "connector_transaction_id",
                }))
            }
        };

        Ok(Self {
            cust_ref: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            receipt,
            amount: router_data.request.minor_amount_to_capture,
            username: auth.username,
            password: auth.password,
        })
    }
}

// Capture Response Transformation (reuses RefundResponseInner)
impl
    TryFrom<
        ResponseRouterData<
            RefundResponseInner,
            RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponseInner,
            RouterDataV2<domain_types::connector_flow::Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map Bambora response code to standard status (0 = Approved)
        let status = if response.response_code == 0 {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        // Handle error responses
        if status == common_enums::AttemptStatus::Failure {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Capture declined".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.receipt.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.receipt.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// PSYNC FLOW TRANSFORMERS
// ============================================================================

// PSync Request Transformation
impl TryFrom<&RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>>
    for BamboraapacSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the connector transaction ID to query
        let receipt = router_data
            .request
            .connector_transaction_id
            .clone()
            .get_connector_transaction_id()
            .change_context(ConnectorError::MissingConnectorTransactionID)?;

        Ok(Self {
            account_number: auth.account_number,
            receipt,
            username: auth.username,
            password: auth.password,
        })
    }
}

// PSync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            BamboraapacSyncResponse,
            RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraapacSyncResponse,
            RouterDataV2<domain_types::connector_flow::PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the query response
        let query_response = &item.response.body.query_transaction_response.query_transaction_result.query_response;

        // Check if response element exists
        let response = match &query_response.response {
            Some(resp) => resp,
            None => {
                // No matching transaction found
                return Ok(Self {
                    resource_common_data: PaymentFlowData {
                        status: common_enums::AttemptStatus::Failure,
                        ..router_data.resource_common_data.clone()
                    },
                    response: Err(ErrorResponse {
                        code: "NO_TRANSACTION_FOUND".to_string(),
                        message: "No matching transaction found".to_string(),
                        reason: Some("Transaction not found in query results".to_string()),
                        status_code: item.http_code,
                        attempt_status: Some(common_enums::AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data.clone()
                });
            }
        };

        // Map Bambora response code to standard status (0 = Approved)
        let status = if response.response_code == 0 {
            if router_data
                .request
                .capture_method
                == Some(common_enums::CaptureMethod::Manual)
            {
                common_enums::AttemptStatus::Authorized
            } else {
                common_enums::AttemptStatus::Charged
            }
        } else {
            common_enums::AttemptStatus::Failure
        };

        // Handle transaction error responses
        if status == common_enums::AttemptStatus::Failure {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Payment declined".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.receipt.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.receipt.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// REFUND FLOW TRANSFORMERS
// ============================================================================

// Refund Request Transformation
impl TryFrom<&RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>>
    for BamboraapacRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the connector transaction ID to refund
        let receipt = router_data
            .request
            .connector_transaction_id
            .clone();

        Ok(Self {
            cust_ref: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            receipt,
            amount: router_data.request.minor_refund_amount,
            username: auth.username,
            password: auth.password,
        })
    }
}

// Refund Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            RefundResponseInner,
            RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    >
    for RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RefundResponseInner,
            RouterDataV2<domain_types::connector_flow::Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map Bambora response code to standard refund status (0 = Approved)
        let refund_status = if response.response_code == 0 {
            common_enums::RefundStatus::Success
        } else {
            common_enums::RefundStatus::Failure
        };

        // Handle error responses
        if refund_status == common_enums::RefundStatus::Failure {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Refund declined".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let refund_response_data = RefundsResponseData {
            connector_refund_id: response.receipt.clone(),
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refund_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// RSYNC FLOW TRANSFORMERS
// ============================================================================

// RSync Request Transformation (reuses BamboraapacSyncRequest)
impl TryFrom<&RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>>
    for BamboraapacSyncRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Get the refund connector transaction ID to query
        let receipt = router_data
            .request
            .connector_refund_id
            .clone();

        Ok(Self {
            account_number: auth.account_number,
            receipt,
            username: auth.username,
            password: auth.password,
        })
    }
}

// RSync Response Transformation
impl
    TryFrom<
        ResponseRouterData<
            BamboraapacSyncResponse,
            RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    >
    for RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraapacSyncResponse,
            RouterDataV2<domain_types::connector_flow::RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let router_data = &item.router_data;

        // Get the query response
        let query_response = &item.response.body.query_transaction_response.query_transaction_result.query_response;

        // Check if response element exists
        let response = match &query_response.response {
            Some(resp) => resp,
            None => {
                // No matching transaction found
                return Ok(Self {
                    resource_common_data: RefundFlowData {
                        status: common_enums::RefundStatus::Failure,
                        ..router_data.resource_common_data.clone()
                    },
                    response: Err(ErrorResponse {
                        code: "NO_TRANSACTION_FOUND".to_string(),
                        message: "No matching refund transaction found".to_string(),
                        reason: Some("Refund transaction not found in query results".to_string()),
                        status_code: item.http_code,
                        attempt_status: None,
                        connector_transaction_id: None,
                        network_decline_code: None,
                        network_advice_code: None,
                        network_error_message: None,
                    }),
                    ..router_data.clone()
                });
            }
        };

        // Map Bambora response code to standard refund status (0 = Approved)
        let refund_status = if response.response_code == 0 {
            common_enums::RefundStatus::Success
        } else {
            common_enums::RefundStatus::Failure
        };

        // Handle transaction error responses
        if refund_status == common_enums::RefundStatus::Failure {
            return Ok(Self {
                resource_common_data: RefundFlowData {
                    status: refund_status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Refund status check failed".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: None,
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let refund_response_data = RefundsResponseData {
            connector_refund_id: response.receipt.clone(),
            refund_status,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: RefundFlowData {
                status: refund_status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(refund_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// SETUP MANDATE FLOW STRUCTURES
// ============================================================================

use domain_types::connector_types::SetupMandateRequestData;

// SetupMandate Request Structure (Customer Registration without payment)
#[derive(Debug, Clone)]
pub struct BamboraapacSetupMandateRequest<
    T: PaymentMethodDataTypes + std::fmt::Debug + std::marker::Sync + std::marker::Send + 'static + Serialize,
> {
    pub customer_storage_number: Option<String>,
    pub cust_number: String,
    pub card_number: Secret<String>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub card_holder_name: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    _phantom: std::marker::PhantomData<T>,
}

impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    > BamboraapacSetupMandateRequest<T>
{
    // Generate SOAP XML request for RegisterSingleCustomer
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:sipp="http://www.ippayments.com.au/interface/api/sipp">
                <soapenv:Header/>
                <soapenv:Body>
                    <sipp:RegisterSingleCustomer>
                        <sipp:registerSingleCustomerXML>
                            <![CDATA[
                <Register>
                    <Customer>
                        <CustNumber>{}</CustNumber>
                        <CreditCard>
                            <CardNumber>{}</CardNumber>
                            <ExpM>{}</ExpM>
                            <ExpY>{}</ExpY>
                            <CardHolderName>{}</CardHolderName>
                        </CreditCard>
                    </Customer>
                    <Security>
                        <UserName>{}</UserName>
                        <Password>{}</Password>
                    </Security>
                </Register>
            ]]>
                        </sipp:registerSingleCustomerXML>
                    </sipp:RegisterSingleCustomer>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.cust_number,
            self.card_number.peek(),
            self.exp_month.peek(),
            self.exp_year.peek(),
            self.card_holder_name.peek(),
            self.username.peek(),
            self.password.peek()
        )
    }
}

// SetupMandate Response Structure (Outer SOAP envelope)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BamboraapacSetupMandateResponse {
    #[serde(rename = "Body")]
    pub body: SetupMandateBodyResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupMandateBodyResponse {
    pub register_single_customer_response: RegisterSingleCustomerResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterSingleCustomerResponse {
    pub register_single_customer_result: String, // HTML-encoded XML string
}

// Inner RegisterSingleCustomerResponse structure (after decoding HTML entities)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterSingleCustomerResponseInner {
    pub return_value: u8,
    pub return_message: Option<String>,
    pub customer_id: Option<String>,
    pub cust_number: String,
    pub action_code: Option<u8>,
}

// ============================================================================
// SETUP MANDATE FLOW TRANSFORMERS
// ============================================================================

// SetupMandate Request Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        &RouterDataV2<
            domain_types::connector_flow::SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    > for BamboraapacSetupMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<
            domain_types::connector_flow::SetupMandate,
            PaymentFlowData,
            SetupMandateRequestData<T>,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract card data from payment method data
        let card_data = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => Ok(card),
            _ => Err(ConnectorError::NotImplemented(
                "Only card payment methods are supported for SetupMandate".to_string(),
            )),
        }?;

        // Convert card number to string
        let card_number_json = serde_json::to_value(&card_data.card_number.0)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let card_number_str = card_number_json
            .as_str()
            .ok_or(ConnectorError::RequestEncodingFailed)?
            .to_string();

        // Generate customer number from customer_id or use connector request reference
        let cust_number = router_data
            .request
            .customer_id
            .as_ref()
            .map(|id| id.get_string_repr().to_string())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        Ok(Self {
            customer_storage_number: None, // Optional: Can be set if merchant wants specific storage numbering
            cust_number,
            card_number: Secret::new(card_number_str),
            exp_month: card_data.card_exp_month.clone(),
            exp_year: card_data.get_expiry_year_4_digit(),
            card_holder_name: card_data
                .card_holder_name
                .clone()
                .unwrap_or_else(|| Secret::new("".to_string())),
            username: auth.username,
            password: auth.password,
            _phantom: std::marker::PhantomData,
        })
    }
}

// SetupMandate Response Transformation
impl<
        T: PaymentMethodDataTypes
            + std::fmt::Debug
            + std::marker::Sync
            + std::marker::Send
            + 'static
            + Serialize,
    >
    TryFrom<
        ResponseRouterData<
            RegisterSingleCustomerResponseInner,
            RouterDataV2<
                domain_types::connector_flow::SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    >
    for RouterDataV2<
        domain_types::connector_flow::SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            RegisterSingleCustomerResponseInner,
            RouterDataV2<
                domain_types::connector_flow::SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response;
        let router_data = &item.router_data;

        // Map Bambora return_value to status
        // 0 = Successful, 1 = Invalid username/password, 2 = User does not belong to API User Group, etc.
        let status = if response.return_value == 0 {
            common_enums::AttemptStatus::Charged
        } else {
            common_enums::AttemptStatus::Failure
        };

        // Handle error responses
        if status == common_enums::AttemptStatus::Failure {
            let error_message = match response.return_value {
                1 => "Invalid username/password",
                2 => "User does not belong to an API User Group",
                4 => "Invalid CustomerStorageNumber",
                99 => "Exception encountered",
                _ => "Customer registration failed",
            };

            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: format!("SETUP_MANDATE_ERROR_{}", response.return_value),
                    message: error_message.to_string(),
                    reason: Some(error_message.to_string()),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: None,
                    network_decline_code: None,
                    network_advice_code: None,
                    network_error_message: Some(error_message.to_string()),
                }),
                ..router_data.clone()
            });
        }

        // Success response - customer registration successful
        // The mandate_reference should contain the customer number for future payments
        let customer_number = router_data
            .request
            .customer_id
            .as_ref()
            .map(|id| id.get_string_repr().to_string())
            .unwrap_or_else(|| {
                router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone()
            });

        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::NoResponseId,
            redirection_data: None,
            mandate_reference: Some(Box::new(domain_types::connector_types::MandateReference {
                connector_mandate_id: Some(customer_number.clone()),
                payment_method_id: None,
            })),
            connector_metadata: Some(serde_json::json!({
                "customer_number": response.cust_number.clone(),
                "customer_id": response.customer_id.clone(),
                "action_code": response.action_code
            })),
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}

// ============================================================================
// REPEAT PAYMENT FLOW STRUCTURES
// ============================================================================

// RepeatPayment Request Structure (Payment with registered customer)
#[derive(Debug, Clone)]
pub struct BamboraapacRepeatPaymentRequest {
    pub account_number: Secret<String>,
    pub customer_storage_number: Option<String>,
    pub cust_number: String,
    pub cust_ref: String,
    pub amount: MinorUnit,
    pub trn_type: BamboraapacTrnType,
    pub username: Secret<String>,
    pub password: Secret<String>,
}

impl BamboraapacRepeatPaymentRequest {
    // Generate SOAP XML request for SubmitSinglePayment with registered customer
    pub fn to_soap_xml(&self) -> String {
        format!(
            r#"
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:dts="http://www.ippayments.com.au/interface/api/dts">
                <soapenv:Body>
                    <dts:SubmitSinglePayment>
                        <dts:trnXML>
                            <![CDATA[
        <Transaction>
            <CustNumber>{}</CustNumber>
            <CustRef>{}</CustRef>
            <Amount>{}</Amount>
            <TrnType>{}</TrnType>
            <AccountNumber>{}</AccountNumber>
            <CreditCard Registered="True"></CreditCard>
            <Security>
                    <UserName>{}</UserName>
                    <Password>{}</Password>
            </Security>
        </Transaction>
                            ]]>
                        </dts:trnXML>
                    </dts:SubmitSinglePayment>
                </soapenv:Body>
            </soapenv:Envelope>
        "#,
            self.cust_number,
            self.cust_ref,
            self.amount.get_amount_as_i64(),
            self.trn_type as i32,
            self.account_number.peek(),
            self.username.peek(),
            self.password.peek()
        )
    }
}

// ============================================================================
// REPEAT PAYMENT FLOW TRANSFORMERS
// ============================================================================

// RepeatPayment Request Transformation
impl TryFrom<&RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>>
    for BamboraapacRepeatPaymentRequest
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        router_data: &RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = BamboraapacAuthType::try_from(&router_data.connector_auth_type)?;

        // Extract the connector mandate ID (customer number) from mandate_reference
        let cust_number = match &router_data.request.mandate_reference {
            domain_types::connector_types::MandateReferenceId::ConnectorMandateId(mandate_ref) => {
                mandate_ref.get_connector_mandate_id().ok_or(
                    ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    },
                )?
            }
            _ => {
                return Err(error_stack::report!(ConnectorError::NotImplemented(
                    "Only ConnectorMandateId is supported for RepeatPayment".to_string()
                )))
            }
        };

        // Determine transaction type based on capture method
        let trn_type = match router_data.request.capture_method {
            Some(common_enums::CaptureMethod::Manual) => BamboraapacTrnType::PreAuth,
            _ => BamboraapacTrnType::Purchase,
        };

        Ok(Self {
            account_number: auth.account_number,
            customer_storage_number: None, // Optional field
            cust_number,
            cust_ref: router_data
                .resource_common_data
                .connector_request_reference_id
                .clone(),
            amount: router_data.request.minor_amount,
            trn_type,
            username: auth.username,
            password: auth.password,
        })
    }
}

// RepeatPayment Response Transformation (reuses BamboraapacPaymentResponse)
impl TryFrom<
        ResponseRouterData<
            BamboraapacPaymentResponse,
            RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    >
    for RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            BamboraapacPaymentResponse,
            RouterDataV2<domain_types::connector_flow::RepeatPayment, PaymentFlowData, RepeatPaymentData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let response = &item.response.body.submit_single_payment_response.submit_single_payment_result.response;
        let router_data = &item.router_data;

        // Map Bambora response code to standard status
        // 0 = Approved, 1 = Not Approved
        let status = if response.response_code == 0 {
            if router_data
                .request
                .capture_method
                == Some(common_enums::CaptureMethod::Manual)
            {
                common_enums::AttemptStatus::Authorized
            } else {
                common_enums::AttemptStatus::Charged
            }
        } else {
            common_enums::AttemptStatus::Failure
        };

        // Handle error responses
        if status == common_enums::AttemptStatus::Failure {
            return Ok(Self {
                resource_common_data: PaymentFlowData {
                    status,
                    ..router_data.resource_common_data.clone()
                },
                response: Err(ErrorResponse {
                    code: response
                        .declined_code
                        .clone()
                        .unwrap_or_else(|| "DECLINED".to_string()),
                    message: response
                        .declined_message
                        .clone()
                        .unwrap_or_else(|| "Payment declined".to_string()),
                    reason: response.declined_message.clone(),
                    status_code: item.http_code,
                    attempt_status: Some(common_enums::AttemptStatus::Failure),
                    connector_transaction_id: Some(response.receipt.clone()),
                    network_decline_code: response.declined_code.clone(),
                    network_advice_code: None,
                    network_error_message: response.declined_message.clone(),
                }),
                ..router_data.clone()
            });
        }

        // Success response
        let payments_response_data = PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(response.receipt.clone()),
            redirection_data: None,
            mandate_reference: None,
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(response.receipt.clone()),
            incremental_authorization_allowed: None,
            status_code: item.http_code,
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..router_data.resource_common_data.clone()
            },
            response: Ok(payments_response_data),
            ..router_data.clone()
        })
    }
}
