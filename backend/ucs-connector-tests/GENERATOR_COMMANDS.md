# Scenario Generator Commands

## Quick Start

### Generate Scenarios for Authorize Suite

```bash
cd /Users/amitsingh.tanwar/Documents/connector-service/connector-service/backend/ucs-connector-tests

# Generate with all groups (multiply all together)
cargo run --bin generate_scenarios -- authorize

# Generate with specific groups (required base + group variants)
cargo run --bin generate_scenarios -- authorize required payment_method_and_capture_settings

# Generate with multiple groups sequentially
cargo run --bin generate_scenarios -- authorize required identification customer_information
```

## Available Groups for Authorize Suite

1. **required** (always processed as base)
   - amount, payment_method, address, auth_type
   
2. **identification**
   - merchant_transaction_id
   
3. **amount_information**
   - order_tax_amount, shipping_cost
   
4. **payment_method_and_capture_settings**
   - capture_method (AUTOMATIC, MANUAL)
   
5. **customer_information**
   - customer.name, customer.email, customer.phone_number, etc.
   
6. **authentication_details**
   - enrolled_for_3ds, authentication_data
   
7. **urls_for_redirection_and_webhooks**
   - return_url, webhook_url, complete_authorize_url
   
8. **session_and_token_information**
   - session_token
   
9. **order_details**
   - order_category, merchant_order_id
   
10. **behavioral_flags_and_preferences**
    - setup_future_usage, off_session, payment_experience, etc.
    
11. **contextual_information**
    - description, payment_channel
    
12. **environment_configuration**
    - test_mode
    
13. **mandate_setup_details**
    - setup_mandate_details
    
14. **state_information**
    - state.access_token.*, state.connector_customer_id

## Command Patterns

### Pattern 1: All Groups (Cartesian Product)
When groups array is empty, all groups are multiplied together:
```bash
cargo run --bin generate_scenarios -- authorize
```

### Pattern 2: Sequential Groups (Base + Variants)
Required is always base. Each additional group creates variants:
```bash
# Base scenarios + capture_method variants
cargo run --bin generate_scenarios -- authorize required payment_method_and_capture_settings

# Base + identification variants + customer_information variants
cargo run --bin generate_scenarios -- authorize required identification customer_information
```

### Pattern 3: Just Required (Minimal)
```bash
cargo run --bin generate_scenarios -- authorize required
```

## Scenario Count Examples

- `authorize required` → 54 scenarios
- `authorize required payment_method_and_capture_settings` → 162 scenarios (54 base + 108 variants)
- `authorize` (all groups) → 54 × (combinations of all other groups)

## Output Location

Generated scenarios are written to:
```
src/global_suites/{suite}_suite/scenario.json
```

For authorize:
```
src/global_suites/authorize_suite/scenario.json
```

## Scenario Naming Convention

- **Base**: `{auth_type}_{payment_method}_{currency}`
  - Example: `NO_THREE_DS_card_USD`
  
- **Variant**: `{base_name}_{field_name}_{variant_value}`
  - Example: `NO_THREE_DS_card_USD_capture_method_manual`
  - Example: `NO_THREE_DS_card_USD_customer_connector_customer_id`

## Assertions

Variant assertions override base assertions:
- Base: `status: [CHARGED, AUTHORIZED]`
- THREE_DS variant: `status: [AUTHENTICATION_PENDING, AUTHORIZED, CHARGED]`
- MANUAL capture: `status: [AUTHORIZED]`

## Files

- **Spec**: `src/global_suites/authorize_suite/generator_specs.json`
- **Payment Methods**: `src/global_suites/authorize_suite/generator_payment_methods.json`
- **Output**: `src/global_suites/authorize_suite/scenario.json`

## Regenerate All Scenarios

To start fresh:
```bash
# Backup old scenarios
mv src/global_suites/authorize_suite/scenario.json src/global_suites/authorize_suite/scenario.json.backup

# Generate new scenarios
cargo run --bin generate_scenarios -- authorize required payment_method_and_capture_settings
```
