use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlAuthorizeResponse {
    #[serde(rename = "reply")]
    pub reply: WorldpayxmlReply,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlReply {
    #[serde(rename = "orderStatus")]
    pub order_status: Option<WorldpayxmlOrderStatus>,
    pub error: Option<WorldpayxmlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlOrderStatus {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub payment: Option<WorldpayxmlPayment>,
    pub error: Option<WorldpayxmlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlPayment {
    pub payment_method: Option<String>,
    pub amount: Option<WorldpayxmlAmountResponse>,
    pub last_event: String,
    #[serde(rename = "AuthorisationId")]
    pub authorisation_id: Option<WorldpayxmlAuthorisationId>,
    #[serde(rename = "ISO8583ReturnCode")]
    pub iso8583_return_code: Option<WorldpayxmlISO8583ReturnCode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorldpayxmlAmountResponse {
    #[serde(rename = "@value")]
    pub value: String,
    #[serde(rename = "@currencyCode")]
    pub currency_code: String,
    #[serde(rename = "@exponent")]
    pub exponent: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorldpayxmlAuthorisationId {
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorldpayxmlISO8583ReturnCode {
    #[serde(rename = "@code")]
    pub code: String,
    #[serde(rename = "@description")]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorldpayxmlError {
    #[serde(rename = "@code")]
    pub code: String,
    #[serde(rename = "$text")]
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlCaptureResponse {
    pub reply: WorldpayxmlCaptureReply,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlCaptureReply {
    pub ok: Option<WorldpayxmlCaptureOk>,
    pub error: Option<WorldpayxmlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlCaptureOk {
    pub capture_received: WorldpayxmlCaptureReceived,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlCaptureReceived {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub amount: Option<WorldpayxmlAmountResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlVoidResponse {
    pub reply: WorldpayxmlVoidReply,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlVoidReply {
    pub ok: Option<WorldpayxmlVoidOk>,
    pub error: Option<WorldpayxmlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlVoidOk {
    pub cancel_received: WorldpayxmlCancelReceived,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlCancelReceived {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlRefundResponse {
    pub reply: WorldpayxmlRefundReply,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlRefundReply {
    pub ok: Option<WorldpayxmlRefundOk>,
    pub error: Option<WorldpayxmlError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlRefundOk {
    pub refund_received: WorldpayxmlRefundReceived,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlRefundReceived {
    #[serde(rename = "@orderCode")]
    pub order_code: String,
    pub amount: Option<WorldpayxmlAmountResponse>,
}

// PSync response can be either XML (PaymentService) or JSON (Webhook format)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WorldpayxmlTransactionResponse {
    Payment(Box<WorldpayxmlAuthorizeResponse>),
    Webhook(WorldpayxmlWebhookResponse),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldpayxmlWebhookResponse {
    pub order_code: Option<String>,
    pub last_event: Option<String>,
    pub payment_status: Option<String>,
}

// Type alias for RSync - reuses PSync response structure
pub type WorldpayxmlRsyncResponse = WorldpayxmlTransactionResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WorldpayxmlErrorResponse {
    // Error response structures will be implemented in flow implementation phase
    Standard(WorldpayxmlStandardError),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorldpayxmlStandardError {
    pub code: Option<String>,
    pub message: Option<String>,
}
