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

use strum::Display;

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum FlowName {
    Authorize,
    Refund,
    Rsync,
    Psync,
    Void,
    SetupMandate,
    Capture,
    AcceptDispute,
    SubmitEvidence,
    DefendDispute,
    CreateOrder,
    IncomingWebhook,
}
