// Stub types for unsupported flows - MANDATORY to avoid compilation errors

use serde::{Deserialize, Serialize};

// Void flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayVoidRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayVoidResponse;

// Capture flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCaptureRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayCaptureResponse;

// Refund flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayRefundResponse;

// Refund Sync flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRefundSyncRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayRefundSyncResponse;

// Create Order flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayCreateOrderRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayCreateOrderResponse;

// Session Token flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySessionTokenRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPaySessionTokenResponse;

// Setup Mandate flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySetupMandateRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPaySetupMandateResponse;

// Repeat Payment flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayRepeatPaymentRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayRepeatPaymentResponse;

// Accept Dispute flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayAcceptDisputeRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayAcceptDisputeResponse;

// Defend Dispute flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPayDefendDisputeRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPayDefendDisputeResponse;

// Submit Evidence flow stubs
#[derive(Debug, Clone, Serialize)]
pub struct ZaakPaySubmitEvidenceRequest;

#[derive(Debug, Clone, Deserialize)]
pub struct ZaakPaySubmitEvidenceResponse;