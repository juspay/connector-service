use common_enums::enums;
use error_stack::ResultExt;

use crate::{errors, global_id::CellId};

crate::global_id_type!(
    GlobalPaymentId,
    "A global id that can be used to identify a payment.

The format will be `<cell_id>_<entity_prefix>_<time_ordered_id>`.

Example: `cell1_pay_uu1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p`"
);

impl GlobalPaymentId {
    /// Get string representation of the id
    pub fn get_string_repr(&self) -> &str {
        self.0.get_string_repr()
    }

    /// Generate a new GlobalPaymentId from a cell id
    pub fn generate(cell_id: &CellId) -> Self {
        let global_id = super::GlobalId::generate(cell_id, super::GlobalEntity::Payment);
        Self(global_id)
    }

    /// Generate the id for revenue recovery Execute PT workflow
    pub fn get_execute_revenue_recovery_id(
        &self,
        task: &str,
        runner: enums::ProcessTrackerRunner,
    ) -> String {
        format!("{runner}_{task}_{}", self.get_string_repr())
    }
}

// TODO: refactor the macro to include this id use case as well
impl TryFrom<std::borrow::Cow<'static, str>> for GlobalPaymentId {
    type Error = error_stack::Report<errors::ValidationError>;
    fn try_from(value: std::borrow::Cow<'static, str>) -> Result<Self, Self::Error> {
        let merchant_ref_id = super::GlobalId::from_string(value).change_context(
            errors::ValidationError::IncorrectValueProvided {
                field_name: "payment_id",
            },
        )?;
        Ok(Self(merchant_ref_id))
    }
}

crate::global_id_type!(
    GlobalAttemptId,
    "A global id that can be used to identify a payment attempt"
);

impl GlobalAttemptId {
    /// Generate a new GlobalAttemptId from a cell id
    #[allow(dead_code)]
    pub fn generate(cell_id: &super::CellId) -> Self {
        let global_id = super::GlobalId::generate(cell_id, super::GlobalEntity::Attempt);
        Self(global_id)
    }

    /// Get string representation of the id
    #[allow(dead_code)]
    pub fn get_string_repr(&self) -> &str {
        self.0.get_string_repr()
    }

    /// Generate the id for Revenue Recovery Psync PT workflow
    #[allow(dead_code)]
    pub fn get_psync_revenue_recovery_id(
        &self,
        task: &str,
        runner: enums::ProcessTrackerRunner,
    ) -> String {
        format!("{runner}_{task}_{}", self.get_string_repr())
    }
}

impl TryFrom<std::borrow::Cow<'static, str>> for GlobalAttemptId {
    type Error = error_stack::Report<errors::ValidationError>;
    fn try_from(value: std::borrow::Cow<'static, str>) -> Result<Self, Self::Error> {
        let global_attempt_id = super::GlobalId::from_string(value).change_context(
            errors::ValidationError::IncorrectValueProvided {
                field_name: "payment_id",
            },
        )?;
        Ok(Self(global_attempt_id))
    }
}
