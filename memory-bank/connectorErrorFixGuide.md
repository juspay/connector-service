# Connector Error Fix Guide

This guide provides step-by-step instructions for fixing errors for a new connector in the connector service.

### File: backend/connector-integration/src/connectors/new_connector/transformers.rs

1. Replace all "enums" with "common_enums"

2. Replace all "Box::new(None)" with "None"

3. Fix moved value errors by storing values in variables before using them multiple times:
   ```rust
   // Instead of using item.response.status twice:
   let status = item.response.status;
   // Then use 'status' variable in both places
   ```

4. **ResponseId enum method errors:**
   - Replace `ResponseId.as_ref()` with `ResponseId.get_connector_transaction_id()`
   - Example: `req.request.connector_transaction_id.get_connector_transaction_id().change_context(errors::ConnectorError::MissingConnectorTransactionID)?`

5. **RawCardNumber generic type access:**
   - Use `ccard.card_number.peek()` to access card number string for generic types
   - Example: `utils::get_card_issuer(ccard.card_number.peek())?`

6. **Amount type conversions:**
   - For StringMinorUnit: Use `StringMinorUnitForConnector.convert(item.request.minor_amount, item.request.currency).change_context(ConnectorError::AmountConversionFailed)?`
     - Import required: `use common_utils::types::{StringMinorUnitForConnector, AmountConvertor};`
     - Don't use `.to_string().into()` as StringMinorUnit doesn't implement From<String>
     - Use `.change_context()` to convert ParsingError to ConnectorError
   - For FloatMajorUnit: Use `FloatMajorUnitForConnector.convert(item.request.minor_refund_amount, item.request.currency).change_context(ConnectorError::AmountConversionFailed)?`
     - Import required: `use common_utils::types::{FloatMajorUnitForConnector, AmountConvertor};`
   - Check available conversion methods for amount types

7. **Missing imports:**
   - Add `ValueExt` trait: `use common_utils::ext_traits::ValueExt;`
   - Add required error handling: `use error_stack::ResultExt;`

8. **Connector metadata helper functions:**
   - Create local helper function instead of using `utils::to_connector_meta`:
   ```rust
   fn to_connector_meta(
       connector_meta: Option<serde_json::Value>,
   ) -> CustomResult<YourMeta, ConnectorError> {
       connector_meta
           .ok_or(ConnectorError::MissingConnectorTransactionID)?
           .parse_value("YourMeta")
           .change_context(ConnectorError::InvalidConnectorConfig {
               config: "connector_metadata",
           })
   }
   ```

### File: backend/connector-integration/src/connectors/new_connector.rs

9. Remove problematic imports:
   - Remove `ObjectReferenceId` from webhooks import
   - Remove `connector_specs` import entirely
   - Remove `api_models` import

10. Fix macro syntax issues:
    - For flows without request body (PSync, RSync), remove `request_body: ()` from `create_all_prerequisites!` macro
    - Use `Json(())` instead of `Json()` for empty request bodies in `macro_connector_implementation!`

11. Remove `connector_metadata: None,` field from ErrorResponse struct

12. Fix field access issues:
    - Use `req.request.field_name` instead of `req.flow_request_data.field_name` for sync operations
    - Use `req.request.field_name` instead of `req.flow_request_data.field_name` for void operations

13. **String field access with type annotations:**
    - For connector_refund_id: Use `req.request.connector_refund_id.as_ref().ok_or(errors::ConnectorError::MissingConnectorRefundID)?`
    - For connector_transaction_id: Use `req.request.connector_transaction_id.get_connector_transaction_id().change_context(errors::ConnectorError::MissingConnectorTransactionID)?`

14. If PSync and RSync don't have request body then remove that from macro implementation.

15. Remove all unused imports from both the new_connector.rs and new_connector/transformer.rs file.

16. Resolve any moved value error using .clone()

17. Remove all raw_connector_response fields

18. If there is any import issue, add that import at the starting of the file.

19. If a field is not present in resource_common_data then use request.

### Common Compilation Error Patterns:

**Error: "no method named `as_ref` found for enum `ResponseId`"**
- Solution: Use `.get_connector_transaction_id()` instead of `.as_ref()`

**Error: "no method named `peek` found for struct `RawCardNumber<T>`"**
- Solution: Use `.peek()` method which is available for generic card number types

**Error: "mismatched types" for amount conversions**
- Solution: Use proper conversion methods like `StringMinorUnit::new()` or check available From/Into implementations

**Error: "cannot find function `to_connector_meta` in module `utils`"**
- Solution: Create a local helper function in your transformers.rs file

**Error: "type annotations needed" for `.as_ref()`**
- Solution: Use specific methods like `.get_connector_transaction_id()` instead of generic `.as_ref()`

**Error: "the trait bound `StringMinorUnit: From<std::string::String>` is not satisfied"**
- Solution: Don't use `.to_string().into()` for StringMinorUnit. Use proper AmountConvertor instead
- Example: `StringMinorUnitForConnector.convert(amount, currency).change_context(ConnectorError::AmountConversionFailed)?`

**Error: "no method named `peek` found for struct `RawCardNumber<T>` in the current scope" (for generic T)**
- Solution: For generic RawCardNumber<T>, use card_issuer or card_network fields instead of trying to peek the card number
- Example approach:
  ```rust
  let card_issuer = if let Some(ref issuer_str) = ccard.card_issuer {
      match issuer_str.as_str() {
          "visa" | "Visa" => utils::CardIssuer::Visa,
          "mastercard" | "Mastercard" => utils::CardIssuer::Master,
          // ... other mappings
      }
  } else if let Some(ref network) = ccard.card_network {
      match network {
          common_enums::CardNetwork::Visa => utils::CardIssuer::Visa,
          // ... other mappings
      }
  } else {
      return Err(ConnectorError::MissingRequiredField { field_name: "card_issuer or card_network" });
  };
  ```

**Error: "? couldn't convert the error to ConnectorError" for AmountConvertor**
- Solution: Use `.change_context(ConnectorError::AmountConversionFailed)?` to convert ParsingError to ConnectorError
- Example: `StringMinorUnitForConnector.convert(amount, currency).change_context(ConnectorError::AmountConversionFailed)?`
