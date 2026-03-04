use grpc_api_types::payments::{
    identifier::IdType, PaymentServiceAuthorizeResponse, PaymentStatus,
};

pub fn assert_payment_status(actual: i32, allowed: &[PaymentStatus], context: &str) {
    let is_allowed = allowed.iter().any(|status| actual == i32::from(*status));
    assert!(
        is_allowed,
        "{context}: unexpected payment status {actual}. Allowed statuses: {:?}",
        allowed
    );
}

pub fn extract_connector_transaction_id(
    response: &PaymentServiceAuthorizeResponse,
) -> Option<String> {
    response
        .connector_transaction_id
        .as_ref()
        .and_then(|identifier| identifier.id_type.as_ref())
        .and_then(|id_type| match id_type {
            IdType::Id(id) | IdType::EncodedData(id) => Some(id.clone()),
            IdType::NoResponseIdMarker(_) => None,
        })
}

pub fn assert_unsupported_error_in_response(response: &PaymentServiceAuthorizeResponse) {
    let Some(error) = response.error.as_ref() else {
        panic!("Expected unsupported error details in response, found none");
    };

    let unified_code = error
        .unified_details
        .as_ref()
        .and_then(|details| details.code.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let unified_message = error
        .unified_details
        .as_ref()
        .and_then(|details| details.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let connector_message = error
        .connector_details
        .as_ref()
        .and_then(|details| details.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let full_message = format!("{unified_message} {connector_message}");
    let has_ir_16 = unified_code.contains("ir_16") || full_message.contains("ir_16");
    let has_unsupported_message = full_message.contains("not supported")
        || full_message.contains("no eligible connector")
        || full_message.contains("payment method type");

    assert!(
        has_ir_16 || has_unsupported_message,
        "Expected unsupported payment method error. code='{unified_code}', message='{full_message}'"
    );
}

pub fn assert_unsupported_error_in_status(status: &tonic::Status) {
    let message = status.message().to_ascii_lowercase();
    assert!(
        message.contains("ir_16")
            || message.contains("not supported")
            || message.contains("no eligible connector")
            || message.contains("payment method type"),
        "Expected unsupported payment method status message, got: {message}"
    );
}

pub fn assert_decline_error_in_response(response: &PaymentServiceAuthorizeResponse) {
    let Some(error) = response.error.as_ref() else {
        panic!("Expected decline error details in response, found none");
    };

    let connector_code = error
        .connector_details
        .as_ref()
        .and_then(|details| details.code.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let connector_message = error
        .connector_details
        .as_ref()
        .and_then(|details| details.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let unified_message = error
        .unified_details
        .as_ref()
        .and_then(|details| details.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let has_decline_signal = connector_code == "2"
        || connector_message.contains("declined")
        || unified_message.contains("declined");

    assert!(
        has_decline_signal,
        "Expected decline signal. connector_code='{connector_code}', connector_message='{connector_message}', unified_message='{unified_message}'"
    );
}

pub fn assert_decline_error_in_status(status: &tonic::Status) {
    let message = status.message().to_ascii_lowercase();
    assert!(
        message.contains("declined")
            || message.contains("transaction")
            || message.contains("failure"),
        "Expected decline-related status message, got: {message}"
    );
}

pub fn assert_no_error(response: &PaymentServiceAuthorizeResponse, context: &str) {
    assert!(
        response.error.is_none(),
        "{context}: expected no error details for success response"
    );
}

pub fn assert_error_details_present(response: &PaymentServiceAuthorizeResponse, context: &str) {
    let Some(error) = response.error.as_ref() else {
        panic!("{context}: expected error details, found none");
    };

    let connector = error
        .connector_details
        .as_ref()
        .expect("Expected connector_details in error");

    let connector_code = connector.code.clone().unwrap_or_default();
    let connector_message = connector.message.clone().unwrap_or_default();

    assert!(
        !connector_code.is_empty(),
        "{context}: connector_details.code should be non-empty"
    );
    assert!(
        !connector_message.is_empty(),
        "{context}: connector_details.message should be non-empty"
    );

    if let Some(unified) = error.unified_details.as_ref() {
        let unified_code = unified.code.clone().unwrap_or_default();
        let unified_message = unified.message.clone().unwrap_or_default();
        assert!(
            !unified_code.is_empty() || !unified_message.is_empty(),
            "{context}: unified_details is present but empty"
        );
    }
}

pub fn assert_decline_error_strict(response: &PaymentServiceAuthorizeResponse) {
    assert_error_details_present(response, "decline");

    let error = response.error.as_ref().expect("error details should exist");
    let connector = error
        .connector_details
        .as_ref()
        .expect("connector_details should exist");

    let connector_code = connector.code.clone().unwrap_or_default();
    let connector_message = connector
        .message
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();

    assert_eq!(
        connector_code, "2",
        "Expected exact Authorize.Net decline code '2'"
    );
    assert!(
        connector_message.contains("declined"),
        "Expected connector decline message to contain 'declined', got '{connector_message}'"
    );
}

pub fn assert_connector_error_code_and_message(
    response: &PaymentServiceAuthorizeResponse,
    expected_code: &str,
    expected_message_substring: &str,
    context: &str,
) {
    assert_error_details_present(response, context);

    let error = response.error.as_ref().expect("error details should exist");
    let connector = error
        .connector_details
        .as_ref()
        .expect("connector_details should exist");

    let connector_code = connector.code.clone().unwrap_or_default();
    let connector_message = connector
        .message
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();

    assert_eq!(
        connector_code, expected_code,
        "{context}: connector_details.code mismatch"
    );

    let expected = expected_message_substring.to_ascii_lowercase();
    assert!(
        connector_message.contains(&expected),
        "{context}: expected connector message to contain '{expected}', got '{connector_message}'"
    );
}

pub fn assert_error_message_contains(
    response: &PaymentServiceAuthorizeResponse,
    needle: &str,
    context: &str,
) {
    assert_error_details_present(response, context);

    let error = response.error.as_ref().expect("error details should exist");
    let unified_message = error
        .unified_details
        .as_ref()
        .and_then(|d| d.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let connector_message = error
        .connector_details
        .as_ref()
        .and_then(|d| d.message.clone())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let expected = needle.to_ascii_lowercase();
    assert!(
        unified_message.contains(&expected) || connector_message.contains(&expected),
        "{context}: expected error message to contain '{expected}'. unified='{unified_message}', connector='{connector_message}'"
    );
}
