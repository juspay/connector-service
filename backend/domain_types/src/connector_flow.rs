#[derive(Debug, Clone)]
pub struct CreateOrder;

#[derive(Debug, Clone)]
pub struct Authorize;

#[derive(Debug, Clone)]
pub struct PSync;

#[derive(Debug, Clone)]
pub struct Void;

#[derive(Debug, Clone)]
pub struct RSync;

#[derive(Debug, Clone)]
pub struct Refund;

#[derive(Debug, Clone)]
pub struct Capture;

#[derive(Debug, Clone)]
pub struct SetupMandate;

#[derive(Debug, Clone)]
pub struct Accept;

#[derive(Debug, Clone)]
pub struct SubmitEvidence;

#[derive(Debug, Clone)]
pub struct DefendDispute;

use strum_macros::Display;

#[derive(Display)]
pub enum FlowName {
    #[strum(serialize = "authorize")]
    Authorize,
    #[strum(serialize = "refund")]
    Refund,
    #[strum(serialize = "rsync")]
    Rsync,
    #[strum(serialize = "psync")]
    Psync,
    #[strum(serialize = "void")]
    Void,
    #[strum(serialize = "setup_mandate")]
    SetupMandate,
    #[strum(serialize = "capture")]
    Capture,
    #[strum(serialize = "accept_dispute")]
    AcceptDispute,
    #[strum(serialize = "submit_evidence")]
    SubmitEvidence,
    #[strum(serialize = "defend_dispute")]
    DefendDispute,
    #[strum(serialize = "create_order")]
    CreateOrder,
    #[strum(serialize = "incoming_webhook")]
    IncomingWebhook,
}
