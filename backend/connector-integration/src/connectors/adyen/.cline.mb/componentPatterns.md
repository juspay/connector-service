# Component Patterns: Adyen Connector

## 1. Adyen-Specific Design Patterns & Logic

*   **API Endpoint Specialization:** Adyen has distinct APIs for different functionalities (e.g., `/payments`, `/modifications` for capture/refund, `/paymentMethods`). The connector logic will be structured to interact with these specific endpoints.
*   **Request/Response Transformers (`transformers.rs`):** This will be a critical part. Adyen's API has rich and sometimes complex request/response structures. `transformers.rs` will handle:
    *   Mapping generic payment request data from `domain_types` to Adyen's specific request fields (e.g., `amount.currency`, `amount.value`, `reference`, `paymentMethod` details, `shopperInteraction`, `returnUrl`).
    *   Handling different Adyen payment method types (e.g., card, iDEAL, Klarna) and their specific data requirements.
    *   Parsing Adyen's responses, including `resultCode` (e.g., "Authorised", "Refused", "Error"), `pspReference`, `action` objects (for 3DS, redirects), and error messages.
    *   Mapping these back to standardized `domain_types` responses and error codes.
*   **Webhook Processing Logic:**
    *   **HMAC Signature Validation:** Adyen webhooks are secured with HMAC signatures; validation is essential.
    *   **Event Type Dispatching:** A handler that switches on `eventType` (e.g., `AUTHORISATION`, `CAPTURE`, `REFUND`, `REPORT_AVAILABLE`) to process each webhook appropriately.
    *   **Idempotency:** Ensuring webhooks are processed exactly once, even if Adyen retries.
*   **Authentication:** Managing Adyen API keys (`X-API-Key` header).
*   **Error Handling:** Mapping Adyen's specific error codes and messages (`errorCode`, `message`, `refusalReason`) to the common error types defined in `connector-integration` or `domain_types`.

## 2. Internal Structure (within `adyen/`)

```mermaid
graph TD
    ParentConnectorTrait[Parent Connector Trait Impl (adyen.rs)] --> AdyenAPIClient[Adyen API Client (adyen.rs or client.rs)]
    ParentConnectorTrait --> RequestTransformer[Request Transformer (transformers.rs)]
    ParentConnectorTrait --> ResponseTransformer[Response Transformer (transformers.rs)]
    ParentConnectorTrait --> WebhookHandler[Webhook Handler (webhooks.rs - potential)]
    
    AdyenAPIClient -->|HTTP Calls| ExternalAdyenAPI[External Adyen API Endpoints]
    
    RequestTransformer -->|Adyen Request Format| AdyenAPIClient
    AdyenAPIClient -->|Adyen Response Format| ResponseTransformer
    
    ExternalAdyenWebhooks[External Adyen Webhooks] --> WebhookHandler
    WebhookHandler -->|Standardized Event| ParentConnectorTrait

    style ParentConnectorTrait fill:#c9f,stroke:#333,stroke-width:2px
    style AdyenAPIClient fill:#ccf,stroke:#333,stroke-width:2px
    style RequestTransformer fill:#cfc,stroke:#333,stroke-width:2px
    style ResponseTransformer fill:#cfc,stroke:#333,stroke-width:2px
    style WebhookHandler fill:#ffc,stroke:#333,stroke-width:2px
    style ExternalAdyenAPI fill:#f99,stroke:#333,stroke-width:2px
    style ExternalAdyenWebhooks fill:#f99,stroke:#333,stroke-width:2px
```

*   **`adyen.rs` (or `mod.rs` if `adyen` is a directory):** Main module file, implements the common connector trait from the parent `connector-integration` crate. Orchestrates calls to transformers and the API client.
*   **`transformers.rs`:** Contains all data mapping logic between `domain_types` and Adyen-specific request/response structures. Likely includes many structs representing parts of Adyen's API.
*   **`client.rs` (potential, or logic within `adyen.rs`):** Handles the actual HTTP communication with Adyen APIs (using `reqwest` or similar), including setting headers (API key, idempotency key), and deserializing responses.
*   **`webhooks.rs` (potential):** Dedicated module for Adyen webhook validation and processing logic.
*   **`types.rs` (potential):** May define Adyen-specific structs that are not directly part of API requests/responses but are useful internally (e.g., for representing Adyen payment method configurations).
*   **`test.rs`:** Unit tests for Adyen-specific logic, especially for transformers and webhook handling. Mocking Adyen API responses will be important here.

## 3. Key Adyen-Specific Concepts to Handle

*   **Payment Session / Advanced Flow:** If using Adyen's newer client-side integrations (Drop-in, Components), there might be logic for `/sessions` API.
*   **Modifications:** Captures, refunds, cancellations are often "modifications" of an original payment.
*   **PSP Reference:** Adyen's unique identifier for a payment, crucial for linking operations.
*   **Action Objects:** Adyen responses can include an `action` object (e.g., for 3D Secure redirects, QR codes, vouchers). The connector needs to translate this into a standardized format if possible, or pass it through.
*   **Idempotency Key:** Using `Idempotency-Key` header for safe retries of mutable operations.

## 4. Data Flows

*   **Outbound (Payment Request):**
    1.  `adyen.rs` receives standardized request.
    2.  `transformers.rs` maps it to Adyen API format.
    3.  `client.rs` sends it to Adyen.
    4.  `client.rs` receives Adyen response.
    5.  `transformers.rs` maps Adyen response to standardized format.
    6.  `adyen.rs` returns standardized response.
*   **Inbound (Webhook):**
    1.  Webhook endpoint (in `grpc-server` or this connector) receives Adyen webhook.
    2.  `webhooks.rs` validates signature and parses event.
    3.  Logic updates payment status or triggers other actions based on event type.
    4.  Generates a standardized internal event.

*(This is an initial draft. Details depend heavily on the specific Adyen APIs being used and the features implemented.)*
