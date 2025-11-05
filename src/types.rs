// Types module with connector enum

use common_enums::PaymentMethodType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectorEnum {
    Payu,
    // Add other connectors here
}

impl ConnectorEnum {
    pub fn get_name(&self) -> &'static str {
        match self {
            ConnectorEnum::Payu => "payu",
        }
    }

    pub fn get_display_name(&self) -> &'static str {
        match self {
            ConnectorEnum::Payu => "PayU",
        }
    }

    pub fn get_supported_payment_methods(&self) -> Vec<PaymentMethodType> {
        match self {
            ConnectorEnum::Payu => vec![
                PaymentMethodType::Upi,
                PaymentMethodType::UpiCollect,
                PaymentMethodType::UpiIntent,
            ],
        }
    }
}

// Type alias for response router data
pub type ResponseRouterData = domain_types::router_response_types::Response;