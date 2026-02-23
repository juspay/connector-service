/**
 * UniFFI FFI example: authorize_req + full round-trip (Node.js)
 *
 * Demonstrates two usage patterns:
 *   1. Low-level: call authorizeReq directly to get the connector HTTP request JSON
 *   2. High-level: use ConnectorClient for a full round-trip (build → HTTP → parse)
 *
 * All types come from proto codegen — Connector, ConnectorAuth, ConnectorConfig
 * follow the same pattern as Currency, CaptureMethod, etc.
 *
 * Prerequisites (run `make setup` first):
 *   - generated/libconnector_service_ffi.dylib  (UniFFI shared library)
 *   - generated/proto.js                        (protobufjs stubs)
 */

"use strict";

const path = require("path");

const SCRIPT_DIR = __dirname;
const SDK_ROOT = path.resolve(SCRIPT_DIR, "..");

const { UniffiClient } = require(path.join(SDK_ROOT, "uniffi_client"));
const { ConnectorClient, Connector, ConnectorConfig } = require(path.join(SDK_ROOT, "connector_client"));
const { ucs } = require(path.join(SDK_ROOT, "generated", "proto"));

const PaymentServiceAuthorizeRequest = ucs.v2.PaymentServiceAuthorizeRequest;
const Currency = ucs.v2.Currency;
const CaptureMethod = ucs.v2.CaptureMethod;
const AuthenticationType = ucs.v2.AuthenticationType;

function buildAuthorizeRequest() {
  return PaymentServiceAuthorizeRequest.create({
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
}

function buildConnectorConfig() {
  const apiKey = process.env.STRIPE_API_KEY || "sk_test_placeholder";
  return {
    connector: Connector.STRIPE,
    auth: { headerKey: { apiKey } },
  };
}

function demoLowLevelFfi(requestMsg) {
  console.log("=== Demo 1: Low-level FFI (authorize_req_transformer) ===\n");

  const config = buildConnectorConfig();
  const configMsg = ConnectorConfig.create(config);
  const configBytes = Buffer.from(ConnectorConfig.encode(configMsg).finish());

  const requestBytes = Buffer.from(
    PaymentServiceAuthorizeRequest.encode(requestMsg).finish()
  );

  console.log(`Request proto bytes: ${requestBytes.length} bytes`);
  console.log(`Config proto bytes:  ${configBytes.length} bytes`);
  console.log(`Connector: STRIPE\n`);

  try {
    const uniffi = new UniffiClient();
    const connectorRequestJson = uniffi.authorizeReq(requestBytes, configBytes);
    const connectorRequest = JSON.parse(connectorRequestJson);

    console.log("Connector HTTP request generated successfully:");
    console.log(`  URL:    ${connectorRequest.url}`);
    console.log(`  Method: ${connectorRequest.method}`);
    console.log(
      `  Headers: ${Object.keys(connectorRequest.headers || {}).join(", ")}`
    );
    console.log("\nFull request JSON:");
    console.log(JSON.stringify(connectorRequest, null, 2));
  } catch (e) {
    console.log("Handler returned an error (FFI boundary is working):");
    console.log(`  ${e.message}`);
    console.log("\nThis is expected with placeholder data. To get a full request,");
    console.log("provide valid STRIPE_API_KEY and complete payment fields.");
  }
}

async function demoFullRoundTrip(requestMsg) {
  console.log("\n=== Demo 2: Full round-trip (ConnectorClient) ===\n");

  const apiKey = process.env.STRIPE_API_KEY || "";
  if (!apiKey || apiKey === "sk_test_placeholder") {
    console.log("Skipping full round-trip: STRIPE_API_KEY not set.");
    console.log("Run with: STRIPE_API_KEY=sk_test_xxx node example.js");
    return;
  }

  const client = new ConnectorClient({
    connector: Connector.STRIPE,
    auth: { headerKey: { apiKey } },
  });

  console.log("Connector: STRIPE");
  console.log("Sending authorize request...\n");

  try {
    const response = await client.authorize(requestMsg);
    console.log("Authorize response received:");
    console.log(JSON.stringify(response, null, 2));
  } catch (e) {
    console.error("Error during round-trip:", e.message);
  }
}

async function main() {
  const request = buildAuthorizeRequest();
  demoLowLevelFfi(request);
  await demoFullRoundTrip(request);
}

main().catch(console.error);
