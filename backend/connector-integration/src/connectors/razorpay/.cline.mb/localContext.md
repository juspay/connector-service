# Local Context: Razorpay Connector

## 1. Component Purpose and Responsibilities

This component (`backend/connector-integration/src/connectors/razorpay/`) is specifically responsible for all interactions with the Razorpay payment gateway. Its duties include:

*   Implementing the standardized connector interface (defined in the parent `connector-integration` component or `domain_types`) for Razorpay-specific operations.
*   Transforming standardized payment requests from the core system into Razorpay API request formats.
*   Handling Razorpay-specific API calls for various payment actions (e.g., creating orders, authorizing payments, capturing payments, issuing refunds, processing webhooks).
*   Interpreting Razorpay API responses (including errors) and transforming them back into the system's standardized format.
*   Managing Razorpay-specific authentication mechanisms (e.g., Key ID and Key Secret).
*   Processing Razorpay webhooks and translating them into standardized internal events.

## 2. Relationship to Overall System

*   **Parent Context:** This Local Memory Bank inherits from and builds upon:
    1.  The Local Memory Bank for the `connector-integration` component (`backend/connector-integration/.cline.mb/`).
    2.  The Root Memory Bank (`/.cline.mb/`).
    Refer to these parent contexts for broader system architecture, shared patterns, and overall project goals.
*   **Used By:** The `connector-integration` component's router/selector logic will delegate requests to this Razorpay connector when Razorpay is the target payment gateway.
*   **Uses:**
    *   Standardized data models from `domain_types`.
    *   Common traits or utilities from the parent `connector-integration` component.
    *   Makes HTTP calls to the Razorpay API endpoints.

## 3. Integration Points

*   **Internal:**
    *   Implements a trait (e.g., `PaymentConnector`) defined by the `connector-integration` component.
    *   Consumes and produces data types from `domain_types`.
*   **External:**
    *   Communicates directly with Razorpay's various API endpoints (e.g., `/orders`, `/payments`, `/refunds`).
    *   Receives webhooks from Razorpay.

## 4. Local Design Decisions (Initial Thoughts)

*   **Order-First Approach:** Razorpay often requires creating an "Order" first before initiating a payment. This flow will be central to the payment creation logic.
*   **API Versioning:** Razorpay API versions will need to be managed if applicable.
*   `transformers.rs`: Will be crucial for mapping between generic payment objects and Razorpay's specific request/response structures (e.g., for orders, payments, amounts in paise).
*   **Webhook Handling:** A dedicated module or functions for validating Razorpay webhook signatures (`X-Razorpay-Signature`) and processing different event types (e.g., `payment.authorized`, `payment.captured`, `payment.failed`, `refund.processed`).
*   `test.rs`: Will contain unit tests specific to Razorpay integration logic.

## 5. Component-Specific Constraints

*   Adherence to Razorpay's API specifications, rate limits, and security requirements.
*   Handling Razorpay's specific error codes and messages.
*   Amounts are typically handled in the smallest currency unit (e.g., paise for INR).
*   Supporting various Razorpay payment methods and flows as required by the project.

*(This is an initial draft. It will be refined as the Razorpay connector's code is analyzed in detail.)*
