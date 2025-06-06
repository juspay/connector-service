# Component Patterns: Razorpay Connector

## 1. Razorpay-Specific Design Patterns & Logic

*   **Order Creation Flow:** A key pattern for Razorpay is often to create an Order (`/orders` API) before attempting a payment. The `order_id` obtained is then used in the payment initiation process. The connector must manage this two-step flow for payment creation.
*   **Request/Response Transformers (`transformers.rs`):**
    *   Mapping generic payment request data from `domain_types` to Razorpay's specific request fields for Orders (e.g., `amount`, `currency`, `receipt`, `notes`) and Payments.
    *   Handling amount conversions (e.g., project uses major units, Razorpay uses minor units like paise).
    *   Parsing Razorpay's responses for Orders, Payments (e.g., `id`, `status`, `error_code`, `error_description`), Captures, and Refunds.
    *   Mapping these back to standardized `domain_types` responses and error codes.
*   **Webhook Processing Logic:**
    *   **Signature Validation:** Verifying the `X-Razorpay-Signature` header using the webhook secret and payload.
    *   **Event Type Dispatching:** Handling various Razorpay events like `order.paid`, `payment.authorized`, `payment.captured`, `payment.failed`, `refund.created`, `refund.processed`.
    *   **Idempotency:** Ensuring webhooks are processed reliably.
*   **Authentication:** Basic Authentication using `Key ID` as username and `Key Secret` as password.
*   **Error Handling:** Mapping Razorpay's specific error structures (e.g., `error.code`, `error.description`, `error.field`) to common error types.
*   **Payment Capture:** Razorpay payments can be authorized first and then captured later. The connector needs to support both direct capture and deferred capture flows.

## 2. Internal Structure (within `razorpay/`)

```mermaid
graph TD
    ParentConnectorTrait[Parent Connector Trait Impl (razorpay.rs)] --> RazorpayAPIClient[Razorpay API Client (razorpay.rs or client.rs)]
    ParentConnectorTrait --> RequestTransformer[Request Transformer (transformers.rs)]
    ParentConnectorTrait --> ResponseTransformer[Response Transformer (transformers.rs)]
    ParentConnectorTrait --> WebhookHandler[Webhook Handler (webhooks.rs - potential)]
    
    RazorpayAPIClient -->|HTTP Calls| ExternalRazorpayAPI[External Razorpay API Endpoints]
    
    RequestTransformer -->|Razorpay Request Format| RazorpayAPIClient
    RazorpayAPIClient -->|Razorpay Response Format| ResponseTransformer
    
    ExternalRazorpayWebhooks[External Razorpay Webhooks] --> WebhookHandler
    WebhookHandler -->|Standardized Event| ParentConnectorTrait

    style ParentConnectorTrait fill:#c9f,stroke:#333,stroke-width:2px
    style RazorpayAPIClient fill:#ccf,stroke:#333,stroke-width:2px
    style RequestTransformer fill:#cfc,stroke:#333,stroke-width:2px
    style ResponseTransformer fill:#cfc,stroke:#333,stroke-width:2px
    style WebhookHandler fill:#ffc,stroke:#333,stroke-width:2px
    style ExternalRazorpayAPI fill:#f99,stroke:#333,stroke-width:2px
    style ExternalRazorpayWebhooks fill:#f99,stroke:#333,stroke-width:2px
```

*   **`razorpay.rs` (or `mod.rs` if `razorpay` is a directory):** Main module file, implements the common connector trait. Orchestrates calls to transformers, order creation, payment processing, and API client.
*   **`transformers.rs`:** Contains all data mapping logic between `domain_types` and Razorpay-specific request/response structures for Orders, Payments, Refunds, etc.
*   **`client.rs` (potential, or logic within `razorpay.rs`):** Handles HTTP communication with Razorpay APIs, including Basic Authentication.
*   **`webhooks.rs` (potential):** Dedicated module for Razorpay webhook signature validation and event processing.
*   **`types.rs` (potential):** May define Razorpay-specific structs not directly part of API models but useful internally.
*   **`test.rs`:** Unit tests for Razorpay-specific logic, especially for transformers, order flow, and webhook handling.

## 3. Key Razorpay-Specific Concepts to Handle

*   **Orders API:** Creating an order is often the first step.
*   **Payments API:** Interacting with payment objects, capturing payments.
*   **Refunds API:** Processing full or partial refunds.
*   **Payment Links (Optional):** If used, specific logic for creating and managing payment links.
*   **Currency and Amount:** Razorpay expects amounts in the smallest currency unit (e.g., paise for INR). Transformations are essential.
*   **Webhook Signature:** `X-Razorpay-Signature` for webhook security.

## 4. Data Flows

*   **Outbound (Payment Request):**
    1.  `razorpay.rs` receives standardized request.
    2.  `transformers.rs` maps it to Razorpay Order API format.
    3.  `client.rs` sends Order creation request to Razorpay.
    4.  `client.rs` receives Order response (with `order_id`).
    5.  (If payment is separate) `transformers.rs` maps data to Payment API format using `order_id`.
    6.  `client.rs` sends Payment request.
    7.  `client.rs` receives Payment response.
    8.  `transformers.rs` maps Razorpay response to standardized format.
    9.  `razorpay.rs` returns standardized response.
*   **Inbound (Webhook):**
    1.  Webhook endpoint receives Razorpay webhook.
    2.  `webhooks.rs` validates signature and parses event.
    3.  Logic updates payment/order status or triggers other actions.
    4.  Generates a standardized internal event.

*(This is an initial draft. Details depend on the specific Razorpay APIs being used and the features implemented.)*
