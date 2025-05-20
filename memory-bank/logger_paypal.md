[2024-06-07] FEEDBACK:
The Paypal connector transformer is not fully implemented. All transformer functions currently throw errors instead of performing the required request/response transformations. The implementation must be completed end-to-end as per the connector implementation guide and Hyperswitch reference.

- The Paypal connector base_url was missing from config/development.toml. It has now been added under the [connectors] section as 'paypal.base_url = "https://api-m.sandbox.paypal.com/"'.
- The Paypal connector was missing the amount_converter field and its initialization, which caused amount conversion errors. This has now been fixed by adding the field and initializing it as in Adyen and Razorpay.

[2024-06-07] ERROR LOG:
- Encountered error: StringMajorUnit constructor is private; cannot use StringMajorUnit(amount) or StringMajorUnit::new(amount). Fix: Use the correct conversion or refactor to use a public API if available.
- Masking import error: Used 'use masking::PeekInterface;' instead of 'use hyperswitch_masking::PeekInterface;'. Fix: Corrected the import.
- PaymentsResponseData is private in transformers module. Fix: Use domain_types::connector_types::PaymentsResponseData directly in paypal.rs.
- Paypal transformer TryFrom implementation: Fixed construction of TransactionResponse variant, ResponseId, and redirection_data.
- Missing Paypal base_url in config/development.toml. Fix: Added 'paypal.base_url = "https://api-m.sandbox.paypal.com/"' under the [connectors] section.
- Missing amount_converter field and initialization in Paypal struct. Fix: Added amount_converter field and initialized it with &StringMajorUnitForConnector, following the pattern in Adyen and Razorpay.
- All errors and fixes were logged and tracked as per build_workflow.md.
