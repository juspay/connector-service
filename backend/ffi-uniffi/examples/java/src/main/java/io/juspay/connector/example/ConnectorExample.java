package io.juspay.connector.example;

import io.juspay.connector.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Complete Java example demonstrating the UniFFI-generated connector bindings.
 *
 * <p>This mirrors the Python {@code example_with_http.py} and shows the full flow:
 * <ol>
 *   <li>Transform payment request → HTTP request  (Rust via UniFFI)</li>
 *   <li>Execute HTTP request                       (Java {@code HttpClient})</li>
 *   <li>Transform HTTP response → Payment result   (Rust via UniFFI)</li>
 * </ol>
 *
 * <p>Run with:
 * <pre>
 *   gradle run -PnativeLibDir=/path/to/target/release
 * </pre>
 */
public class ConnectorExample {

    // ---------------------------------------------------------------
    //  Entry point
    // ---------------------------------------------------------------

    public static void main(String[] args) {
        printBanner("UniFFI Connector Client - Java Full Flow Demo");
        System.out.println();
        System.out.println("This demo shows the complete integration:");
        System.out.println("  1. Rust/UniFFI: Transforms payment data -> HTTP request");
        System.out.println("  2. Java:        Executes the HTTP request");
        System.out.println("  3. Rust/UniFFI: Transforms HTTP response -> Payment result");
        System.out.println();

        try {
            demoListConnectors();
            demoConnectorInfo();
            demoDryRunAuthorize();
            demoMockResponseFlow();
            demoConnectorRegistry();
            demoRealApiCall();
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }

        printBanner("Demo completed!");
    }

    // ---------------------------------------------------------------
    //  Demo 1 – List supported connectors
    // ---------------------------------------------------------------

    private static void demoListConnectors() {
        printBanner("1. List Supported Connectors");

        List<String> connectors = Connector_ffi_uniffiKt.listSupportedConnectors();
        System.out.println("Supported connectors: " + connectors);
        System.out.println();
    }

    // ---------------------------------------------------------------
    //  Demo 2 – Get connector info
    // ---------------------------------------------------------------

    private static void demoConnectorInfo() {
        printBanner("2. Connector Info");

        String[] names = {"stripe", "adyen", "checkout"};
        for (String name : names) {
            ConnectorInfo info = Connector_ffi_uniffiKt.getConnectorInfo(name);
            if (info != null) {
                System.out.println("  " + info.getName());
                System.out.println("    Display name   : " + info.getDisplayName());
                System.out.println("    Base URL       : " + info.getBaseUrl());
                System.out.println("    Auth type      : " + info.getAuthType());
                System.out.println("    Auth fields    : " + info.getAuthFields());
                System.out.println("    Supported flows: " + info.getSupportedFlows());
                System.out.println("    Body format    : " + info.getBodyFormat());
                System.out.println("    3-DS support   : " + info.getSupports3ds());
                System.out.println();
            } else {
                System.out.println("  " + name + ": not found");
            }
        }
    }

    // ---------------------------------------------------------------
    //  Demo 3 – Dry-run authorize (no HTTP call)
    // ---------------------------------------------------------------

    private static void demoDryRunAuthorize() {
        printBanner("3. Dry-Run Authorize (Stripe)");

        // Create a card payment method via the Rust helper
        PaymentMethod card = Connector_ffi_uniffiKt.createCardPaymentMethod(
                "4242424242424242",  // number
                12,                  // exp_month
                2025,                // exp_year
                "123",               // cvc
                "Test User"          // holder_name
        );

        // Build payment data
        PaymentData payment = new PaymentData(
                2500L,           // amount (cents)
                "USD",           // currency
                card,            // payment_method
                "order_12345",   // reference_id
                null,            // transaction_id
                null,            // return_url
                null             // metadata
        );

        // Auth credentials
        Map<String, String> auth = new HashMap<>();
        auth.put("api_key", "sk_test_YOUR_KEY_HERE");

        // Transform to HTTP request via Rust
        TransformRequestInput requestInput = new TransformRequestInput(
                "stripe",
                "authorize",
                auth,
                payment
        );

        HttpRequest httpRequest = Connector_ffi_uniffiKt.transformRequest(requestInput);

        System.out.println("Transformed HTTP request:");
        System.out.println("  URL           : " + httpRequest.getUrl());
        System.out.println("  Method        : " + httpRequest.getMethod());
        System.out.println("  Headers       : " + httpRequest.getHeaders().keySet());
        System.out.println("  Body format   : " + httpRequest.getBodyFormat());
        if (httpRequest.getBody() != null) {
            String body = httpRequest.getBody();
            if (body.length() > 200) body = body.substring(0, 200) + "...";
            System.out.println("  Body          : " + body);
        }
        System.out.println();

        // --- Also demonstrate Adyen ---
        System.out.println("--- Adyen Dry-Run ---");

        Map<String, String> adyenAuth = new HashMap<>();
        adyenAuth.put("api_key", "YOUR_ADYEN_API_KEY");
        adyenAuth.put("merchant_account", "YOUR_MERCHANT_ACCOUNT");

        PaymentMethod adyenCard = Connector_ffi_uniffiKt.createCardPaymentMethod(
                "4111111111111111", 3, 2026, "737", "John Doe"
        );

        PaymentData adyenPayment = new PaymentData(
                1500L, "EUR", adyenCard, null, null, null, null
        );

        HttpRequest adyenReq = Connector_ffi_uniffiKt.transformRequest(
                new TransformRequestInput("adyen", "authorize", adyenAuth, adyenPayment)
        );

        System.out.println("  URL    : " + adyenReq.getUrl());
        System.out.println("  Method : " + adyenReq.getMethod());
        System.out.println("  Body   : " + truncate(adyenReq.getBody(), 200));
        System.out.println();
    }

    // ---------------------------------------------------------------
    //  Demo 4 – Full mock response flow
    // ---------------------------------------------------------------

    private static void demoMockResponseFlow() {
        printBanner("4. Mock Response Flow (Stripe authorize → transform response)");

        // Step 1: Build and transform request
        PaymentMethod card = Connector_ffi_uniffiKt.createCardPaymentMethod(
                "4242424242424242", 12, 2025, "123", "Test User"
        );

        PaymentData payment = new PaymentData(
                5000L, "USD", card, "mock_order_1", null, null, null
        );

        Map<String, String> auth = new HashMap<>();
        auth.put("api_key", "sk_test_mock");

        HttpRequest httpRequest = Connector_ffi_uniffiKt.transformRequest(
                new TransformRequestInput("stripe", "authorize", auth, payment)
        );

        System.out.println("STEP 1 – Request transformed by Rust:");
        System.out.println("  URL    : " + httpRequest.getUrl());
        System.out.println("  Method : " + httpRequest.getMethod());

        // Step 2: Simulate a successful Stripe response
        String mockResponse = "{"
                + "\"id\":\"pi_mock_12345\","
                + "\"status\":\"requires_capture\","
                + "\"amount\":5000,"
                + "\"currency\":\"usd\","
                + "\"payment_method\":\"pm_card_visa\""
                + "}";

        System.out.println();
        System.out.println("STEP 2 – Mock HTTP response:");
        System.out.println("  Status : 200");
        System.out.println("  Body   : " + mockResponse);

        // Step 3: Transform the response via Rust
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("content-type", "application/json");

        TransformResponseInput responseInput = new TransformResponseInput(
                "stripe",
                "authorize",
                (short) 200,
                responseHeaders,
                mockResponse
        );

        PaymentResult result = Connector_ffi_uniffiKt.transformResponse(responseInput);

        System.out.println();
        System.out.println("STEP 3 – Result transformed by Rust:");
        System.out.println("  Success        : " + result.getSuccess());
        System.out.println("  Status         : " + result.getStatus());
        System.out.println("  Transaction ID : " + result.getTransactionId());
        System.out.println("  Amount         : " + result.getAmount());
        System.out.println("  Currency       : " + result.getCurrency());

        // --- Simulate an error response ---
        System.out.println();
        System.out.println("--- Simulating Error Response ---");

        String errorResponse = "{"
                + "\"error\":{"
                + "\"code\":\"card_declined\","
                + "\"message\":\"Your card was declined.\","
                + "\"type\":\"card_error\""
                + "}"
                + "}";

        PaymentResult errorResult = Connector_ffi_uniffiKt.transformResponse(
                new TransformResponseInput(
                        "stripe", "authorize",
                        (short) 402,
                        new HashMap<>(),
                        errorResponse
                )
        );

        System.out.println("  Success       : " + errorResult.getSuccess());
        System.out.println("  Status        : " + errorResult.getStatus());
        System.out.println("  Error Code    : " + errorResult.getErrorCode());
        System.out.println("  Error Message : " + errorResult.getErrorMessage());
        System.out.println();
    }

    // ---------------------------------------------------------------
    //  Demo 5 – ConnectorRegistry object
    // ---------------------------------------------------------------

    private static void demoConnectorRegistry() {
        printBanner("5. ConnectorRegistry Object");

        ConnectorRegistry registry = new ConnectorRegistry();

        List<String> connectors = registry.listConnectors();
        System.out.println("Connectors from registry: " + connectors);

        for (String name : connectors) {
            ConnectorInfo info = registry.getConnectorInfo(name);
            if (info != null) {
                List<PaymentFlow> flows = registry.getSupportedFlows(name);
                System.out.println("  " + info.getDisplayName() + " -> flows: " + flows);
            }
        }
        System.out.println();
    }

    // ---------------------------------------------------------------
    //  Demo 6 – Real API call (commented out by default)
    // ---------------------------------------------------------------

    private static void demoRealApiCall() {
        printBanner("6. Real API Call (requires valid Stripe test key)");
        System.out.println("To make a real API call, uncomment the code in demoRealApiCall()");
        System.out.println("and provide a valid Stripe test API key.");
        System.out.println();

        /*
        // Uncomment and set your Stripe test key to run a live call.
        String apiKey = "sk_test_YOUR_REAL_KEY_HERE";

        Map<String, String> auth = new HashMap<>();
        auth.put("api_key", apiKey);

        ConnectorClient client = new ConnectorClient("stripe", auth);

        Map<String, Object> result = client.authorize(
                1000L,                   // $10.00
                "USD",
                "4242424242424242",       // Stripe test card
                12, 2025, "123",
                "Test User",
                "test_order_001"
        );

        System.out.println("Real API result: " + result);

        // If authorized, try capture
        Object txnId = result.get("transaction_id");
        if (Boolean.TRUE.equals(result.get("success")) && txnId != null) {
            System.out.println("Attempting capture...");
            Map<String, Object> captureResult = client.capture(txnId.toString(), 1000L, "USD");
            System.out.println("Capture result: " + captureResult);
        }
        */
    }

    // ---------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------

    private static void printBanner(String title) {
        String line = "=".repeat(60);
        System.out.println(line);
        System.out.println(title);
        System.out.println(line);
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "null";
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
