# Component Progress: Razorpay Connector

## 1. Component-Specific Implementation Status

*   **Overall Status:** Initial setup. Local Memory Bank files created. Code analysis pending.
*   **Current Focus:** Understanding the specific files within `backend/connector-integration/src/connectors/razorpay/` (i.e., `transformers.rs`, `test.rs` and the main `razorpay.rs` or `mod.rs`) and how they implement Razorpay-specific logic, especially the order-first flow.

## 2. Key Files Status (within `razorpay/`)

| File / Module        | Status          | Key Responsibilities (Inferred)                                     | Next Steps (for MB & Code)                                                                                                |
| :------------------- | :-------------- | :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------ |
| **`razorpay.rs` (or `mod.rs`)** | Unknown  | Main Razorpay connector logic, trait implementation, orchestration. | Review to understand order creation, payment flow, and use of transformers.                                               |
| **`transformers.rs`**| Unknown         | Data mapping for Orders, Payments, Refunds between `domain_types` and Razorpay API formats. | Detailed analysis of request/response structs and mapping functions. Crucial for amount conversions.                    |
| **`client.rs` (if exists)** | Unknown    | HTTP client logic for Razorpay API calls, authentication.           | Review API call construction, Basic Auth.                                                                                 |
| **`webhooks.rs` (if exists)** | Unknown  | Razorpay webhook validation (`X-Razorpay-Signature`) and processing. | Review event handling and signature validation.                                                                           |
| **`types.rs` (if exists)** | Unknown     | Razorpay-specific internal types.                                   | Review any custom types defined for Razorpay.                                                                             |
| **`test.rs`**        | Unknown         | Unit tests for Razorpay connector logic.                              | Analyze test cases, especially for order flow, payment capture, refunds, and webhook processing.                          |

## 3. Current Work Focus (Within This Razorpay Component)

*   **MB Population:** Detailing `localContext.md` and `componentPatterns.md` based on inferred structure and common Razorpay integration patterns.
*   **Code Skimming:** A high-level pass over the files in the `razorpay/` directory.

## 4. Known Issues and Challenges (Razorpay-Specific)

*   None identified yet from a Memory Bank perspective.
*   **Order Management:** The two-step order creation then payment flow needs careful handling.
*   **Amount Conversion:** Consistently handling amounts in paise (minor unit) versus major units used elsewhere.
*   **Webhook Reliability:** Ensuring robust webhook processing and signature verification.
*   **API Error Granularity:** Mapping Razorpay's potentially detailed error fields to a standardized error model.

## 5. Planned Improvements / Next Steps (Development)

*   *(To be filled in after code review and understanding current capabilities)*
*   **Short-term (MB):**
    1.  Thoroughly review `transformers.rs` for order, payment, and refund mappings, paying attention to amount handling.
    2.  Analyze how `razorpay.rs` (or `mod.rs`) implements the common connector trait and manages the order-payment sequence.
    3.  Examine `test.rs` to understand tested scenarios.
    4.  Update `localContext.md` and `componentPatterns.md` with concrete findings from the code.

## 6. Recent Changes (Within This Razorpay Component)

*   Created initial Local Memory Bank files for the Razorpay connector:
    *   `backend/connector-integration/src/connectors/razorpay/.cline.mb/localContext.md`
    *   `backend/connector-integration/src/connectors/razorpay/.cline.mb/componentPatterns.md`
    *   `backend/connector-integration/src/connectors/razorpay/.cline.mb/componentProgress.md` (this file)

*(This file will track the detailed progress of the Razorpay connector component.)*
