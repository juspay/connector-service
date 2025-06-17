pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("connector_service_descriptor");

pub mod payments {
    tonic::include_proto!("ucs.payments");
}

pub mod health_check {
    tonic::include_proto!("grpc.health.v1");
}

// Serde helper functions for enum string deserialization
pub fn deserialize_enum_from_string<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum EnumOrString {
        String(String),
        Int(i32),
    }
    
    match EnumOrString::deserialize(deserializer)? {
        EnumOrString::String(s) => {
            // Try to parse as enum name first
            if let Some(val) = payments::Currency::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::PaymentMethod::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::AuthenticationType::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::PaymentMethodType::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::CaptureMethod::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::FutureUsage::from_str_name(&s) {
                return Ok(val as i32);
            }
            if let Some(val) = payments::PaymentExperience::from_str_name(&s) {
                return Ok(val as i32);
            }
            
            Err(serde::de::Error::custom(format!("Unknown enum value: {}", s)))
        }
        EnumOrString::Int(i) => Ok(i),
    }
}

pub fn deserialize_option_enum_from_string<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OptionalEnumOrString {
        String(String),
        Int(i32),
        None,
    }
    
    match Option::<OptionalEnumOrString>::deserialize(deserializer)? {
        Some(OptionalEnumOrString::String(s)) => {
            // Try to parse as enum name first
            if let Some(val) = payments::PaymentMethodType::from_str_name(&s) {
                return Ok(Some(val as i32));
            }
            if let Some(val) = payments::CaptureMethod::from_str_name(&s) {
                return Ok(Some(val as i32));
            }
            if let Some(val) = payments::FutureUsage::from_str_name(&s) {
                return Ok(Some(val as i32));
            }
            if let Some(val) = payments::PaymentExperience::from_str_name(&s) {
                return Ok(Some(val as i32));
            }
            
            Err(serde::de::Error::custom(format!("Unknown enum value: {}", s)))
        }
        Some(OptionalEnumOrString::Int(i)) => Ok(Some(i)),
        Some(OptionalEnumOrString::None) | None => Ok(None),
    }
}
