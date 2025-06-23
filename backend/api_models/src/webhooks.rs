use common_utils::id_type::PaymentIdType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorWebhookSecrets {
    pub secret: Vec<u8>,
    pub additional_secret: Option<hyperswitch_masking::Secret<String>>,
}

#[derive(Clone)]
pub enum AuthenticationIdType {
    AuthenticationId(String),
    ConnectorAuthenticationId(String),
}

#[derive(Clone)]
pub enum MandateIdType {
    MandateId(String),
    ConnectorMandateId(String),
}

#[derive(Clone)]
pub enum RefundIdType {
    RefundId(String),
    ConnectorRefundId(String),
}

#[derive(Clone)]
pub enum ObjectReferenceId {
    PaymentId(PaymentIdType),
    RefundId(RefundIdType),
    MandateId(MandateIdType),
    ExternalAuthenticationID(AuthenticationIdType),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
#[serde(rename_all = "snake_case")]
pub enum IncomingWebhookEvent {
    /// Authorization + Capture success
    PaymentIntentFailure,
    /// Authorization + Capture failure
    PaymentIntentSuccess,
    PaymentIntentProcessing,
    PaymentIntentPartiallyFunded,
    PaymentIntentCancelled,
    PaymentIntentCancelFailure,
    PaymentIntentAuthorizationSuccess,
    PaymentIntentAuthorizationFailure,
    PaymentIntentCaptureSuccess,
    PaymentIntentCaptureFailure,
    PaymentActionRequired,
    EventNotSupported,
    SourceChargeable,
    SourceTransactionCreated,
    RefundFailure,
    RefundSuccess,
    DisputeOpened,
    DisputeExpired,
    DisputeAccepted,
    DisputeCancelled,
    DisputeChallenged,
    // dispute has been successfully challenged by the merchant
    DisputeWon,
    // dispute has been unsuccessfully challenged
    DisputeLost,
    MandateActive,
    MandateRevoked,
    EndpointVerification,
    ExternalAuthenticationARes,
    FrmApproved,
    FrmRejected,
}
