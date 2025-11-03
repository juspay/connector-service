use common_enums::{CountryAlpha2, Currency};

pub const SUPPORTED_CURRENCIES: &[Currency] = &[
    Currency::INR,
];

pub const SUPPORTED_COUNTRIES: &[CountryAlpha2] = &[
    CountryAlpha2::IN,
];

#[derive(Debug, Clone, Copy)]
pub enum EaseBuzzEndpoints {
    EaseBuzInitiatePayment,
    EasebuzSeamlessTransaction,
    EasebuzTxnSync,
    EaseBuzRefund,
    EaseBuzRefundSync,
    EasebuzzSubmitOtp,
    EasebuzzResendOtp,
    GetEMIOptions,
    EasebuzGetPlans,
    DelayedSettlement,
    DelayedSettlementStatus,
    EasebuzzAuthzRequest,
    GenerateAccessKey,
    MandateCreation,
    MandateRetrieve,
    PresentmentRequestInitiate,
    DebitRequestRetrieve,
    UpiAutopay,
    NotificationReq,
    UpiMandateExecute,
    RevokeMandate,
    MandateNotificationSyncReq,
}

pub fn get_endpoint(endpoint: EaseBuzzEndpoints, test_mode: bool) -> &'static str {
    match (endpoint, test_mode) {
        (EaseBuzzEndpoints::EaseBuzInitiatePayment, true) => "/payment/initiateLink",
        (EaseBuzzEndpoints::EaseBuzInitiatePayment, false) => "/payment/initiateLink",
        (EaseBuzzEndpoints::EasebuzSeamlessTransaction, true) => "/pay/initiate",
        (EaseBuzzEndpoints::EasebuzSeamlessTransaction, false) => "/pay/initiate",
        (EaseBuzzEndpoints::EasebuzTxnSync, true) => "/transaction/status",
        (EaseBuzzEndpoints::EasebuzTxnSync, false) => "/transaction/status",
        (EaseBuzzEndpoints::EaseBuzRefund, true) => "/transaction/refund",
        (EaseBuzzEndpoints::EaseBuzRefund, false) => "/transaction/refund",
        (EaseBuzzEndpoints::EaseBuzRefundSync, true) => "/transaction/refundStatus",
        (EaseBuzzEndpoints::EaseBuzRefundSync, false) => "/transaction/refundStatus",
        (EaseBuzzEndpoints::EasebuzzSubmitOtp, true) => "/auth/submitOTP",
        (EaseBuzzEndpoints::EasebuzzSubmitOtp, false) => "/auth/submitOTP",
        (EaseBuzzEndpoints::EasebuzzResendOtp, true) => "/auth/resendOTP",
        (EaseBuzzEndpoints::EasebuzzResendOtp, false) => "/auth/resendOTP",
        (EaseBuzzEndpoints::GetEMIOptions, true) => "/emi/getEMIOptions",
        (EaseBuzzEndpoints::GetEMIOptions, false) => "/emi/getEMIOptions",
        (EaseBuzzEndpoints::EasebuzGetPlans, true) => "/plans/getPlans",
        (EaseBuzzEndpoints::EasebuzGetPlans, false) => "/plans/getPlans",
        (EaseBuzzEndpoints::DelayedSettlement, true) => "/settlement/create",
        (EaseBuzzEndpoints::DelayedSettlement, false) => "/settlement/create",
        (EaseBuzzEndpoints::DelayedSettlementStatus, true) => "/settlement/status",
        (EaseBuzzEndpoints::DelayedSettlementStatus, false) => "/settlement/status",
        (EaseBuzzEndpoints::EasebuzzAuthzRequest, true) => "/auth/authorize",
        (EaseBuzzEndpoints::EasebuzzAuthzRequest, false) => "/auth/authorize",
        (EaseBuzzEndpoints::GenerateAccessKey, true) => "/auth/accessKey",
        (EaseBuzzEndpoints::GenerateAccessKey, false) => "/auth/accessKey",
        (EaseBuzzEndpoints::MandateCreation, true) => "/mandate/create",
        (EaseBuzzEndpoints::MandateCreation, false) => "/mandate/create",
        (EaseBuzzEndpoints::MandateRetrieve, true) => "/mandate/retrieve",
        (EaseBuzzEndpoints::MandateRetrieve, false) => "/mandate/retrieve",
        (EaseBuzzEndpoints::PresentmentRequestInitiate, true) => "/mandate/execute",
        (EaseBuzzEndpoints::PresentmentRequestInitiate, false) => "/mandate/execute",
        (EaseBuzzEndpoints::DebitRequestRetrieve, true) => "/mandate/debitStatus",
        (EaseBuzzEndpoints::DebitRequestRetrieve, false) => "/mandate/debitStatus",
        (EaseBuzzEndpoints::UpiAutopay, true) => "/upi/autopay",
        (EaseBuzzEndpoints::UpiAutopay, false) => "/upi/autopay",
        (EaseBuzzEndpoints::NotificationReq, true) => "/notification/send",
        (EaseBuzzEndpoints::NotificationReq, false) => "/notification/send",
        (EaseBuzzEndpoints::UpiMandateExecute, true) => "/upi/execute",
        (EaseBuzzEndpoints::UpiMandateExecute, false) => "/upi/execute",
        (EaseBuzzEndpoints::RevokeMandate, true) => "/mandate/revoke",
        (EaseBuzzEndpoints::RevokeMandate, false) => "/mandate/revoke",
        (EaseBuzzEndpoints::MandateNotificationSyncReq, true) => "/notification/sync",
        (EaseBuzzEndpoints::MandateNotificationSyncReq, false) => "/notification/sync",
    }
}

pub fn get_base_url() -> &'static str {
    "https://pay.easebuzz.in"
}