package io.juspay.connector.example;

import io.juspay.connector.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * High-level Java client that wraps the UniFFI-generated Kotlin/JVM bindings
 * and handles HTTP execution.
 *
 * <p>Architecture:
 * <pre>
 *   Java (this class)          Rust (via UniFFI)
 *   ─────────────────          ─────────────────
 *   authorize(...)  ──────►  transformRequest(...)  ──► HttpRequest
 *        │                                                  │
 *        │◄────────── execute HTTP (Java HttpClient) ◄──────┘
 *        │
 *        ▼
 *   HttpResponse     ──────►  transformResponse(...) ──► PaymentResult
 * </pre>
 */
public class ConnectorClient {

    private final String connector;
    private final Map<String, String> auth;
    private final ConnectorInfo info;
    private final HttpClient httpClient;

    /**
     * Create a new client for the given connector.
     *
     * @param connector  connector name (stripe, adyen, checkout, etc.)
     * @param auth       authentication credentials
     * @throws IllegalArgumentException if the connector is unknown
     */
    public ConnectorClient(String connector, Map<String, String> auth) {
        this.connector = connector.toLowerCase();
        this.auth = auth;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        this.info = Connector_ffi_uniffiKt.getConnectorInfo(this.connector);
        if (this.info == null) {
            throw new IllegalArgumentException("Unknown connector: " + connector);
        }
    }

    public ConnectorInfo getInfo() {
        return info;
    }

    // ---------------------------------------------------------------
    //  Payment operations
    // ---------------------------------------------------------------

    /**
     * Authorize a card payment.
     *
     * @return map with result fields (success, status, transaction_id, etc.)
     */
    public Map<String, Object> authorize(long amount, String currency,
                                         String cardNumber, int expMonth, int expYear,
                                         String cvc, String holderName,
                                         String referenceId) {
        PaymentMethod card = Connector_ffi_uniffiKt.createCardPaymentMethod(
                cardNumber, expMonth, expYear, cvc, holderName
        );

        PaymentData payment = new PaymentData(
                amount, currency, card, referenceId, null, null, null
        );

        return executeFlow("authorize", payment);
    }

    /**
     * Capture a previously authorized payment.
     */
    public Map<String, Object> capture(String transactionId, long amount, String currency) {
        PaymentData payment = new PaymentData(
                amount, currency, null, null, transactionId, null, null
        );
        return executeFlow("capture", payment);
    }

    /**
     * Void / cancel a payment.
     */
    public Map<String, Object> voidPayment(String transactionId) {
        PaymentData payment = new PaymentData(
                0L, "USD", null, null, transactionId, null, null
        );
        return executeFlow("void", payment);
    }

    /**
     * Refund a payment.
     */
    public Map<String, Object> refund(String transactionId, long amount, String currency) {
        PaymentData payment = new PaymentData(
                amount, currency, null, null, transactionId, null, null
        );
        return executeFlow("refund", payment);
    }

    // ---------------------------------------------------------------
    //  Core flow: transform → execute → transform
    // ---------------------------------------------------------------

    private Map<String, Object> executeFlow(String flow, PaymentData payment) {
        // Step 1: Transform request via Rust
        TransformRequestInput requestInput = new TransformRequestInput(
                connector, flow, auth, payment
        );
        io.juspay.connector.HttpRequest httpRequest =
                Connector_ffi_uniffiKt.transformRequest(requestInput);

        System.out.println("  [" + flow.toUpperCase() + "] " + httpRequest.getMethod()
                + " " + httpRequest.getUrl());

        // Step 2: Execute HTTP
        HttpResult httpResult = executeHttp(httpRequest);

        System.out.println("  [" + flow.toUpperCase() + "] HTTP " + httpResult.statusCode);

        // Step 3: Transform response via Rust
        TransformResponseInput responseInput = new TransformResponseInput(
                connector, flow,
                (short) httpResult.statusCode,
                httpResult.headers,
                httpResult.body
        );

        PaymentResult result = Connector_ffi_uniffiKt.transformResponse(responseInput);

        // Pack into a simple map for the caller
        Map<String, Object> out = new HashMap<>();
        out.put("success", result.getSuccess());
        out.put("status", result.getStatus().toString());
        out.put("transaction_id", result.getTransactionId());
        out.put("connector_transaction_id", result.getConnectorTransactionId());
        out.put("amount", result.getAmount());
        out.put("currency", result.getCurrency());
        out.put("error_code", result.getErrorCode());
        out.put("error_message", result.getErrorMessage());
        return out;
    }

    // ---------------------------------------------------------------
    //  HTTP execution
    // ---------------------------------------------------------------

    private HttpResult executeHttp(io.juspay.connector.HttpRequest ffiRequest) {
        try {
            java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(ffiRequest.getUrl()))
                    .timeout(Duration.ofSeconds(30));

            // Set headers
            for (Map.Entry<String, String> entry : ffiRequest.getHeaders().entrySet()) {
                builder.header(entry.getKey(), entry.getValue());
            }

            // Set method + body
            String body = ffiRequest.getBody();
            java.net.http.HttpRequest.BodyPublisher bodyPublisher =
                    (body != null && !body.isEmpty())
                            ? java.net.http.HttpRequest.BodyPublishers.ofString(body)
                            : java.net.http.HttpRequest.BodyPublishers.noBody();

            switch (ffiRequest.getMethod()) {
                case GET:
                    builder.GET();
                    break;
                case POST:
                    builder.POST(bodyPublisher);
                    break;
                case PUT:
                    builder.PUT(bodyPublisher);
                    break;
                case DELETE:
                    builder.DELETE();
                    break;
                case PATCH:
                    builder.method("PATCH", bodyPublisher);
                    break;
            }

            HttpResponse<String> response = httpClient.send(
                    builder.build(),
                    HttpResponse.BodyHandlers.ofString()
            );

            Map<String, String> responseHeaders = new HashMap<>();
            response.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) responseHeaders.put(k, v.get(0));
            });

            return new HttpResult(response.statusCode(), responseHeaders, response.body());

        } catch (Exception e) {
            Map<String, String> emptyHeaders = new HashMap<>();
            return new HttpResult(0, emptyHeaders, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    private static class HttpResult {
        final int statusCode;
        final Map<String, String> headers;
        final String body;

        HttpResult(int statusCode, Map<String, String> headers, String body) {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }
    }
}
