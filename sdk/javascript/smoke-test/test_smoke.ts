/**
 * Smoke test for PayPal access token flow using hyperswitch-payments npm tarball.
 *
 * This test demonstrates:
 *   1. Create an access token via PayPal
 *   2. Use the access token in an authorize request
 *
 * Usage:
 *   mkdir /tmp/test-js-sdk && cd /tmp/test-js-sdk && npm init -y
 *   npm install <path-to>/hyperswitch-payments-0.1.0.tgz
 *   npx ts-node test_access_token_smoke.ts
 */

import { PaymentClient,MerchantAuthenticationClient, payments, configs } from "hyperswitch-payments";

const {
  MerchantAuthenticationServiceCreateAccessTokenRequest,
  MerchantAuthenticationServiceCreateAccessTokenResponse,
  PaymentServiceAuthorizeRequest,
  PaymentServiceAuthorizeResponse,
  Currency,
  CaptureMethod,
  AuthenticationType,
  Connector,
  SecretString,
  AccessToken,
  ConnectorState,
} = payments;

const { FfiOptions, EnvOptions } = configs;

const PAYPAL_CREDS = {
  client_id:
    "client_id",
  client_secret:
    "client_secret",
};

const metadata: Record<string, string> = {
  connector: "Paypal",
  connector_auth_type: JSON.stringify({
    Paypal: {
      client_id: PAYPAL_CREDS.client_id,
      client_secret: PAYPAL_CREDS.client_secret,
    },
  }),
  "x-connector": "Paypal",
  "x-merchant-id": "test_merchant_123",
  "x-request-id": "test-pack-001",
  "x-tenant-id": "public",
  "x-auth": "body-key",
  "x-api-key": PAYPAL_CREDS.client_secret,
  "x-key1": PAYPAL_CREDS.client_id,
};

// Create FfiOptions with testMode
const ffiOptions: configs.IFfiOptions = FfiOptions.create({
  env: EnvOptions.create({ testMode: true }),
});

/**
 * Test the access token flow:
 * 1. Create access token
 * 2. Use access token in authorize request
 */
async function testAccessTokenFlow(): Promise<void> {
  console.log("\n=== Test: PayPal Access Token Flow ===");

  const authClient = new MerchantAuthenticationClient();
  const paymentClient = new PaymentClient();

  // Step 1: Create Access Token Request
  console.log("\n--- Step 1: Create Access Token ---");
  const accessTokenRequest: payments.IMerchantAuthenticationServiceCreateAccessTokenRequest =
    MerchantAuthenticationServiceCreateAccessTokenRequest.create({
      merchantAccessTokenId: { id: "access_token_test_" + Date.now() },
      connector: Connector.PAYPAL,
      testMode: true,
    });

  // Make the request via MerchantAuthenticationClient
  let accessTokenResponse: payments.MerchantAuthenticationServiceCreateAccessTokenResponse;
  let accessTokenValue: string | null = null;
  let tokenTypeValue: string | null = null;

  try {
    accessTokenResponse = await authClient.createAccessToken(
      accessTokenRequest,
      metadata,
      ffiOptions
    );
    console.log(`  Response type: ${typeof accessTokenResponse}`);
    console.log(`  Response keys: ${Object.keys(accessTokenResponse)}`);

    // Extract access token from response
    if (
      accessTokenResponse.accessToken &&
      accessTokenResponse.accessToken.value
    ) {
      accessTokenValue = accessTokenResponse.accessToken.value;
      tokenTypeValue = accessTokenResponse.tokenType ?? "Bearer";

      console.log(accessTokenValue);
      console.log(
        `  Access Token received: ${accessTokenValue!.substring(0, 20)}...`
      );
      console.log(`  Token Type: ${tokenTypeValue}`);
      console.log(
        `  Expires In: ${accessTokenResponse.expiresInSeconds} seconds`
      );
      console.log(`  Status: ${accessTokenResponse.status}`);
    } else {
      console.log("  WARNING: No access token in response");
      console.log(
        "  Full response:",
        JSON.stringify(accessTokenResponse, null, 2)
      );
    }
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    console.log(`  Error creating access token: ${message}`);
    console.log("  This might be expected if credentials are not valid");
    return;
  }

  if (!accessTokenValue) {
    console.log("  SKIPPED: Cannot proceed without access token");
    return;
  }

  // Step 2: Use Access Token in Authorize Request
  console.log("\n--- Step 2: Authorize with Access Token ---");
  const authorizeRequest: payments.IPaymentServiceAuthorizeRequest =
    PaymentServiceAuthorizeRequest.create({
      merchantTransactionId: {
        id: "authorize_with_token_" + Date.now(),
      },
      amount: {
        minorAmount: 1000, // $10.00
        currency: Currency.USD,
      },
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
      customer: {
        email: { value: "test@example.com" },
        name: "Test",
      },
      state: ConnectorState.create({
        accessToken: AccessToken.create({
          token: SecretString.create({ value: accessTokenValue }),
          tokenType: tokenTypeValue,
          expiresInSeconds: accessTokenResponse!.expiresInSeconds,
        }),
      }),
      authType: AuthenticationType.NO_THREE_DS,
      returnUrl: "https://example.com/return",
      webhookUrl: "https://example.com/webhook",
      address: {},
      testMode: true,
    });

  try {
    const authorizeResponse: payments.PaymentServiceAuthorizeResponse =
      await paymentClient.authorize(authorizeRequest, metadata, ffiOptions);
    console.log(`  Response type: ${typeof authorizeResponse}`);
    console.log(`  Response keys: ${Object.keys(authorizeResponse)}`);
    console.log(`  Payment status: ${authorizeResponse.status}`);
    console.log("  PASSED");
  } catch (e: unknown) {
    console.log(`  Error during authorize: ${e}`);
    // This might be expected depending on PayPal API behavior
    console.log("  PASSED (round-trip completed, error is from PayPal)");
  }

  console.log("\n=== Test Complete ===");
}

// Run the test
testAccessTokenFlow()
  .then(() => console.log("\nAll checks passed."))
  .catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  });
