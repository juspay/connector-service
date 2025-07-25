//! Integrity checking framework for payment flows
//!
//! This module provides a comprehensive integrity checking system for payment operations.
//! It ensures that request and response data remain consistent across connector interactions
//! by comparing critical fields like amounts, currencies, and transaction identifiers.

use common_utils::errors::IntegrityCheckError;
// Domain type imports
use domain_types::connector_types::{
    AcceptDisputeData, DisputeDefendData, PaymentCreateOrderData, PaymentVoidData,
    PaymentsAuthorizeData, PaymentsCaptureData, PaymentsSyncData, RefundSyncData, RefundsData,
    RepeatPaymentData, SetupMandateRequestData, SubmitEvidenceData,
};
use domain_types::router_request_types::{
    AcceptDisputeIntegrityObject, AuthoriseIntegrityObject, CaptureIntegrityObject,
    CreateOrderIntegrityObject, DefendDisputeIntegrityObject, PaymentSynIntegrityObject,
    PaymentVoidIntegrityObject, RefundIntegrityObject, RefundSyncIntegrityObject,
    RepeatPaymentIntegrityObject, SetupMandateIntegrityObject, SubmitEvidenceIntegrityObject,
};

// ========================================================================
// CORE TRAITS
// ========================================================================

/// Trait for integrity objects that can perform field-by-field comparison
pub trait FlowIntegrity {
    /// The integrity object type for this flow
    type IntegrityObject;

    /// Compare request and response integrity objects
    ///
    /// # Arguments
    /// * `req_integrity_object` - Integrity object derived from the request
    /// * `res_integrity_object` - Integrity object derived from the response
    /// * `connector_transaction_id` - Optional transaction ID for error context
    ///
    /// # Returns
    /// * `Ok(())` if all fields match
    /// * `Err(IntegrityCheckError)` if there are mismatches
    fn compare(
        req_integrity_object: Self::IntegrityObject,
        res_integrity_object: Self::IntegrityObject,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}

/// Trait for data types that can provide integrity objects
pub trait GetIntegrityObject<T: FlowIntegrity> {
    /// Extract integrity object from response data
    fn get_response_integrity_object(&self) -> Option<T::IntegrityObject>;

    /// Generate integrity object from request data
    fn get_request_integrity_object(&self) -> T::IntegrityObject;
}

/// Trait for data types that can perform integrity checks
pub trait CheckIntegrity<Request, T> {
    /// Perform integrity check between request and response
    ///
    /// # Arguments
    /// * `request` - The request object containing integrity data
    /// * `connector_transaction_id` - Optional transaction ID for error context
    ///
    /// # Returns
    /// * `Ok(())` if integrity check passes or no response integrity object exists
    /// * `Err(IntegrityCheckError)` if integrity check fails
    fn check_integrity(
        &self,
        request: &Request,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError>;
}

// ========================================================================
// CHECK INTEGRITY IMPLEMENTATIONS
// ========================================================================

/// Generic implementation of CheckIntegrity that works for all payment flow types.
/// This implementation:
/// 1. Checks if response has an integrity object
/// 2. If yes, compares it with request integrity object
/// 3. If no, passes the check (no integrity validation needed)
macro_rules! impl_check_integrity {
    ($data_type:ty) => {
        impl<T, Request> CheckIntegrity<Request, T> for $data_type
        where
            T: FlowIntegrity,
            Request: GetIntegrityObject<T>,
        {
            fn check_integrity(
                &self,
                request: &Request,
                connector_transaction_id: Option<String>,
            ) -> Result<(), IntegrityCheckError> {
                match request.get_response_integrity_object() {
                    Some(res_integrity_object) => {
                        let req_integrity_object = request.get_request_integrity_object();
                        T::compare(
                            req_integrity_object,
                            res_integrity_object,
                            connector_transaction_id,
                        )
                    }
                    None => Ok(()),
                }
            }
        }
    };
}

// Apply the macro to all payment flow data types
impl_check_integrity!(PaymentsAuthorizeData);
impl_check_integrity!(PaymentCreateOrderData);
impl_check_integrity!(SetupMandateRequestData);
impl_check_integrity!(PaymentsSyncData);
impl_check_integrity!(PaymentVoidData);
impl_check_integrity!(RefundsData);
impl_check_integrity!(PaymentsCaptureData);
impl_check_integrity!(AcceptDisputeData);
impl_check_integrity!(DisputeDefendData);
impl_check_integrity!(RefundSyncData);
impl_check_integrity!(SubmitEvidenceData);
impl_check_integrity!(RepeatPaymentData);

// ========================================================================
// GET INTEGRITY OBJECT IMPLEMENTATIONS
// ========================================================================

impl GetIntegrityObject<AuthoriseIntegrityObject> for PaymentsAuthorizeData {
    fn get_response_integrity_object(&self) -> Option<AuthoriseIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> AuthoriseIntegrityObject {
        AuthoriseIntegrityObject {
            amount: self.minor_amount,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<CreateOrderIntegrityObject> for PaymentCreateOrderData {
    fn get_response_integrity_object(&self) -> Option<CreateOrderIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> CreateOrderIntegrityObject {
        CreateOrderIntegrityObject {
            amount: self.amount,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<SetupMandateIntegrityObject> for SetupMandateRequestData {
    fn get_response_integrity_object(&self) -> Option<SetupMandateIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> SetupMandateIntegrityObject {
        SetupMandateIntegrityObject {
            amount: self.minor_amount,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<PaymentSynIntegrityObject> for PaymentsSyncData {
    fn get_response_integrity_object(&self) -> Option<PaymentSynIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> PaymentSynIntegrityObject {
        PaymentSynIntegrityObject {
            amount: self.amount,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<PaymentVoidIntegrityObject> for PaymentVoidData {
    fn get_response_integrity_object(&self) -> Option<PaymentVoidIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> PaymentVoidIntegrityObject {
        PaymentVoidIntegrityObject {
            connector_transaction_id: self.connector_transaction_id.clone(),
        }
    }
}

impl GetIntegrityObject<RefundIntegrityObject> for RefundsData {
    fn get_response_integrity_object(&self) -> Option<RefundIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> RefundIntegrityObject {
        RefundIntegrityObject {
            refund_amount: self.minor_refund_amount,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<CaptureIntegrityObject> for PaymentsCaptureData {
    fn get_response_integrity_object(&self) -> Option<CaptureIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> CaptureIntegrityObject {
        CaptureIntegrityObject {
            amount_to_capture: self.minor_amount_to_capture,
            currency: self.currency,
        }
    }
}

impl GetIntegrityObject<AcceptDisputeIntegrityObject> for AcceptDisputeData {
    fn get_response_integrity_object(&self) -> Option<AcceptDisputeIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> AcceptDisputeIntegrityObject {
        AcceptDisputeIntegrityObject {
            connector_dispute_id: self.connector_dispute_id.clone(),
        }
    }
}

impl GetIntegrityObject<DefendDisputeIntegrityObject> for DisputeDefendData {
    fn get_response_integrity_object(&self) -> Option<DefendDisputeIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> DefendDisputeIntegrityObject {
        DefendDisputeIntegrityObject {
            connector_dispute_id: self.connector_dispute_id.clone(),
            defense_reason_code: self.defense_reason_code.clone(),
        }
    }
}

impl GetIntegrityObject<RefundSyncIntegrityObject> for RefundSyncData {
    fn get_response_integrity_object(&self) -> Option<RefundSyncIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> RefundSyncIntegrityObject {
        RefundSyncIntegrityObject {
            connector_transaction_id: self.connector_transaction_id.clone(),
            connector_refund_id: self.connector_refund_id.clone(),
        }
    }
}

impl GetIntegrityObject<SubmitEvidenceIntegrityObject> for SubmitEvidenceData {
    fn get_response_integrity_object(&self) -> Option<SubmitEvidenceIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> SubmitEvidenceIntegrityObject {
        SubmitEvidenceIntegrityObject {
            connector_dispute_id: self.connector_dispute_id.clone(),
        }
    }
}

impl GetIntegrityObject<RepeatPaymentIntegrityObject> for RepeatPaymentData {
    fn get_response_integrity_object(&self) -> Option<RepeatPaymentIntegrityObject> {
        self.integrity_object.clone()
    }

    fn get_request_integrity_object(&self) -> RepeatPaymentIntegrityObject {
        RepeatPaymentIntegrityObject {
            amount: self.amount,
            currency: self.currency,
            mandate_reference: match &self.mandate_reference {
                domain_types::connector_types::MandateReferenceId::ConnectorMandateId(
                    mandate_ref,
                ) => mandate_ref
                    .get_connector_mandate_id()
                    .unwrap_or_default()
                    .to_string(),
                domain_types::connector_types::MandateReferenceId::NetworkMandateId(
                    network_mandate,
                ) => network_mandate.clone(),
                domain_types::connector_types::MandateReferenceId::NetworkTokenWithNTI(_) => {
                    String::new()
                }
            },
        }
    }
}

// ========================================================================
// FLOW INTEGRITY IMPLEMENTATIONS
// ========================================================================

impl FlowIntegrity for AuthoriseIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for CreateOrderIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for SetupMandateIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        // Handle optional amount field
        match (req_integrity_object.amount, res_integrity_object.amount) {
            (Some(req_amount), Some(res_amount)) if req_amount != res_amount => {
                mismatched_fields.push(format_mismatch(
                    "amount",
                    &req_amount.to_string(),
                    &res_amount.to_string(),
                ));
            }
            (None, Some(_)) | (Some(_), None) => {
                mismatched_fields.push("amount is missing in request or response".to_string());
            }
            _ => {}
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for PaymentSynIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for PaymentVoidIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.connector_transaction_id
            != res_integrity_object.connector_transaction_id
        {
            mismatched_fields.push(format_mismatch(
                "connector_transaction_id",
                &req_integrity_object.connector_transaction_id,
                &res_integrity_object.connector_transaction_id,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for RefundIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.refund_amount != res_integrity_object.refund_amount {
            mismatched_fields.push(format_mismatch(
                "refund_amount",
                &req_integrity_object.refund_amount.to_string(),
                &res_integrity_object.refund_amount.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for CaptureIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.amount_to_capture != res_integrity_object.amount_to_capture {
            mismatched_fields.push(format_mismatch(
                "amount_to_capture",
                &req_integrity_object.amount_to_capture.to_string(),
                &res_integrity_object.amount_to_capture.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for AcceptDisputeIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.connector_dispute_id != res_integrity_object.connector_dispute_id {
            mismatched_fields.push(format_mismatch(
                "connector_dispute_id",
                &req_integrity_object.connector_dispute_id,
                &res_integrity_object.connector_dispute_id,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for DefendDisputeIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.connector_dispute_id != res_integrity_object.connector_dispute_id {
            mismatched_fields.push(format_mismatch(
                "connector_dispute_id",
                &req_integrity_object.connector_dispute_id,
                &res_integrity_object.connector_dispute_id,
            ));
        }

        if req_integrity_object.defense_reason_code != res_integrity_object.defense_reason_code {
            mismatched_fields.push(format_mismatch(
                "defense_reason_code",
                &req_integrity_object.defense_reason_code,
                &res_integrity_object.defense_reason_code,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for RefundSyncIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.connector_transaction_id
            != res_integrity_object.connector_transaction_id
        {
            mismatched_fields.push(format_mismatch(
                "connector_transaction_id",
                &req_integrity_object.connector_transaction_id,
                &res_integrity_object.connector_transaction_id,
            ));
        }

        if req_integrity_object.connector_refund_id != res_integrity_object.connector_refund_id {
            mismatched_fields.push(format_mismatch(
                "connector_refund_id",
                &req_integrity_object.connector_refund_id,
                &res_integrity_object.connector_refund_id,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for SubmitEvidenceIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.connector_dispute_id != res_integrity_object.connector_dispute_id {
            mismatched_fields.push(format_mismatch(
                "connector_dispute_id",
                &req_integrity_object.connector_dispute_id,
                &res_integrity_object.connector_dispute_id,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

impl FlowIntegrity for RepeatPaymentIntegrityObject {
    type IntegrityObject = Self;

    fn compare(
        req_integrity_object: Self,
        res_integrity_object: Self,
        connector_transaction_id: Option<String>,
    ) -> Result<(), IntegrityCheckError> {
        let mut mismatched_fields = Vec::new();

        if req_integrity_object.amount != res_integrity_object.amount {
            mismatched_fields.push(format_mismatch(
                "amount",
                &req_integrity_object.amount.to_string(),
                &res_integrity_object.amount.to_string(),
            ));
        }

        if req_integrity_object.currency != res_integrity_object.currency {
            mismatched_fields.push(format_mismatch(
                "currency",
                &req_integrity_object.currency.to_string(),
                &res_integrity_object.currency.to_string(),
            ));
        }

        if req_integrity_object.mandate_reference != res_integrity_object.mandate_reference {
            mismatched_fields.push(format_mismatch(
                "mandate_reference",
                &req_integrity_object.mandate_reference,
                &res_integrity_object.mandate_reference,
            ));
        }

        check_integrity_result(mismatched_fields, connector_transaction_id)
    }
}

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

/// Helper function to format field mismatch messages
#[inline]
fn format_mismatch(field: &str, expected: &str, found: &str) -> String {
    format!("{field} expected {expected} but found {found}")
}

/// Helper function to generate integrity check result
#[inline]
fn check_integrity_result(
    mismatched_fields: Vec<String>,
    connector_transaction_id: Option<String>,
) -> Result<(), IntegrityCheckError> {
    if mismatched_fields.is_empty() {
        Ok(())
    } else {
        let field_names = mismatched_fields.join(", ");
        Err(IntegrityCheckError {
            field_names,
            connector_transaction_id,
        })
    }
}
