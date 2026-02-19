/**
 * UniFFI FFI example: authorizeReq + full round-trip (Node.js via koffi)
 *
 * Demonstrates two usage patterns:
 *   1. Low-level: call authorizeReq directly to get the connector HTTP request JSON
 *   2. High-level: use ConnectorClient for a full round-trip (build -> HTTP -> parse)
 *
 * Uses the same UniFFI shared library as the Python and Kotlin examples.
 * No NAPI required — koffi calls the C ABI directly.
 *
 * Prerequisites (run `make setup` first):
 *   - generated/libconnector_service_ffi.dylib  (UniFFI shared library)
 *   - generated/proto.js                        (static protobuf module)
 *   - node_modules/koffi                        (npm install)
 */

"use strict";

const { UniffiClient } = require("./uniffi_client");
const { ConnectorClient } = require("./connector_client");
const { ucs } = require("./generated/proto");

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const Currency = ucs.v2.Currency;
const CaptureMethod = ucs.v2.CaptureMethod;
const AuthenticationType = ucs.v2.AuthenticationType;

function buildMetadata() {
  const apiKey = process.env.STRIPE_API_KEY || "sk_test_placeholder";
  return {
    connector: "Stripe",
    connector_auth_type: JSON.stringify({
      auth_type: "HeaderKey",
      api_key: apiKey,
    }),
    "x-connector": "Stripe",
    "x-merchant-id": "test_merchant_123",
    "x-request-id": "test-request-001",
    "x-tenant-id": "public",
    "x-auth": "body-key",
    "x-api-key": apiKey,
  };
}

function demoLowLevelFfi(requestBytes) {
  console.log("=== Demo 1: Low-level FFI (authorizeReq) ===\n");

  const metadata = buildMetadata();
  const uniffi = new UniffiClient();

  console.log(`Request proto bytes: ${requestBytes.length} bytes`);
  console.log(`Connector: ${metadata.connector}\n`);

  try {
    const connectorRequestJson = uniffi.authorizeReq(requestBytes, metadata);
    const connectorRequest = JSON.parse(connectorRequestJson);

    console.log("Connector HTTP request generated successfully:");
    console.log(`  URL:    ${connectorRequest.url}`);
    console.log(`  Method: ${connectorRequest.method}`);
    console.log(`  Headers: ${Object.keys(connectorRequest.headers || {})}`);
    console.log(`\nFull request JSON:`);
    console.log(JSON.stringify(connectorRequest, null, 2));
  } catch (e) {
    if (e.message.includes("HandlerError")) {
      console.log("Handler returned an error (FFI boundary is working):");
      console.log(`  ${e.message}`);
      console.log("\nThis is expected with placeholder data. To get a full request,");
      console.log("provide valid STRIPE_API_KEY and complete payment fields.");
    } else {
      console.error(`FFI error: ${e.message}`);
      process.exit(1);
    }
  }
}

async function demoFullRoundTrip(requestMsg) {
  console.log("\n=== Demo 2: Full round-trip (ConnectorClient) ===\n");

  const apiKey = process.env.STRIPE_API_KEY || "";
  if (!apiKey || apiKey === "sk_test_placeholder") {
    console.log("Skipping full round-trip: STRIPE_API_KEY not set.");
    console.log("Run with: STRIPE_API_KEY=sk_test_xxx node main.js");
    return;
  }

  const metadata = buildMetadata();
  const client = new ConnectorClient();

  console.log(`Connector: ${metadata.connector}`);
  console.log("Sending authorize request...\n");

  try {
    const response = await client.authorize(requestMsg, metadata);
    console.log("Authorize response received:");
    console.log(JSON.stringify(response, null, 2));
  } catch (e) {
    console.error(`Error during round-trip: ${e.message}`);
  }
}

async function main() {
  // Build protobuf request using pre-generated static proto module.
  // No runtime .proto file loading needed.
  const requestMsg = PaymentServiceAuthorizeRequest.create({
    requestRefId: { id: "test_payment_123456" },
    amount: 1000,
    minorAmount: 1000,
    currency: Currency.USD,
    captureMethod: CaptureMethod.AUTOMATIC,
    paymentMethod: {
      card: {
        cardNumber: { value: "4111111111111111" },
        cardExpMonth: { value: "12" },
        cardExpYear: { value: "2050" },
        cardCvc: { value: "123" },
        cardHolderName: { value: "Test User" },
      },
    },
    email: { value: "customer@example.com" },
    customerName: "Test Customer",
    authType: AuthenticationType.NO_THREE_DS,
    enrolledFor_3ds: false,
    returnUrl: "https://example.com/return",
    webhookUrl: "https://example.com/webhook",
    address: {},
    description: "Test payment",
    testMode: true,
  });

  // Pre-serialize for the low-level demo (raw FFI call needs bytes)
  const requestBytes = Buffer.from(
    PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
  );

  demoLowLevelFfi(requestBytes);
  await demoFullRoundTrip(requestMsg);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
