import { randomUUID } from "node:crypto";
import {
  stripeConnectedAccount,
  stripePaymentIntent,
  assertStripeSandboxKey,
} from "./stripe.js";
import { test, expect } from "@playwright/test";
import {
  assertOtp,
  loadCredentials,
  loadRunConfig,
  resolveOverrides,
  merge,
  type Json,
} from "./config.js";
import { Hyperswitch, assertUcsGateway } from "./hs.js";
import { paymentCases, type Connector, type RequestVariant } from "./cases.js";

export function paymentDefaults(_connector: Connector): Json {
  return {
    amount: 6000,
    currency: "USD",
    authentication_type: "no_three_ds",
    payment_method: "card",
    payment_method_type: "credit",
    setup_future_usage: null,
    customer_acceptance: null,
    email: "ucs-e2e@example.com",
    return_url: "https://example.com",
    browser_info: {
      accept_header:
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      language: "en-US",
      screen_height: 1080,
      screen_width: 1920,
      color_depth: 24,
      user_agent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
      time_zone: 0,
      java_enabled: false,
      java_script_enabled: true,
      ip_address: "192.0.2.1",
    },
    payment_method_data: {
      card: {
        card_number: "4242424242424242",
        card_exp_month: "03",
        card_exp_year: "30",
        card_holder_name: "John Doe",
        card_cvc: "123",
      },
    },
    billing: {
      address: {
        first_name: "John",
        last_name: "Doe",
        line1: "1467 Harrison Street",
        city: "San Francisco",
        state: "CA",
        zip: "94122",
        country: "US",
      },
    },
  };
}

export function otpSuite(
  connector: Connector,
  variants: readonly RequestVariant[] = [],
) {
  const runConfig = loadRunConfig(connector);
  for (const requestVariant of paymentCases(
    variants,
    process.env.E2E_VARIANT,
  )) {
    const overrides = resolveOverrides(
      runConfig.document,
      connector,
      requestVariant,
    );
    test.describe(`${connector}/${requestVariant.id}`, () => {
      for (const variant of requestVariant.scenarios) {
        const title = variant;
        test(`${title} @otp @no3ds @${connector}`, async ({}, info) => {
          info.annotations.push({
            type: "execution",
            description: "live sandbox: HS → UCS → processor",
          });
          const admin = process.env.HS_ADMIN_API_KEY ?? "test_admin";
          const auth = loadCredentials(connector, runConfig.credential);
          assertStripeSandboxKey(auth);
          const merchantId = `e2e_${randomUUID().replaceAll("-", "")}`;
          const hs = await Hyperswitch.create();
          try {
            await hs.enableUcs(admin);
            const account = await hs.call("POST", "/accounts", admin, {
              merchant_name: "UCS Playwright OTP",
              primary_business_details: [
                { country: "US", business: "default" },
              ],
              merchant_id: merchantId,
            });
            const apiKey = await hs.call(
              "POST",
              `/api_keys/${merchantId}`,
              admin,
              {
                name: "UCS E2E",
                expiration: new Date(Date.now() + 86_400_000).toISOString(),
                description: "Disposable sandbox e2e test key",
              },
            );
            const key = apiKey.api_key;
            expect(typeof key).toBe("string");
            let profileId = account.default_profile;
            if (!profileId) {
              const profile = await hs.call(
                "POST",
                `/account/${merchantId}/business_profile`,
                key,
                { profile_name: "ucs-e2e" },
              );
              profileId = profile.profile_id;
            }
            expect(typeof profileId).toBe("string");
            if (overrides.profile) {
              await hs.call(
                "POST",
                `/account/${merchantId}/business_profile/${profileId}`,
                key,
                overrides.profile,
              );
            }
            const mca = await hs.call(
              "POST",
              `/account/${merchantId}/connectors`,
              key,
              {
                connector_account_details: auth.connector_account_details,
                metadata: merge(
                  auth.metadata ?? {},
                  overrides.connectorMetadata,
                ),
                payment_methods_enabled: [],
                connector_type: "payment_processor",
                connector_name: connector,
                connector_label: `${connector}_e2e`,
                profile_id: profileId,
                test_mode: true,
                disabled: false,
              },
            );
            expect(typeof mca.merchant_connector_id).toBe("string");
            const routing = await hs.call("POST", "/routing", key, {
              name: "ucs-e2e",
              description: "Single sandbox connector",
              profile_id: profileId,
              algorithm: {
                type: "single",
                data: {
                  connector,
                  merchant_connector_id: mca.merchant_connector_id,
                },
              },
            });
            await hs.call("POST", `/routing/${routing.id}/activate`, key, {
              profile_id: profileId,
            });
            const body = merge(paymentDefaults(connector), overrides.payment);
            if (requestVariant.fixture === "stripe-connect") {
              body.split_payments.stripe_split_payment.transfer_account_id =
                await stripeConnectedAccount(
                  auth,
                  body.split_payments.stripe_split_payment.transfer_account_id,
                );
            }
            assertOtp(body);
            const inlineConfirm = body.confirm === true;
            const createBody = structuredClone(body);
            if (requestVariant.clientConfirmation) {
              delete createBody.payment_method;
              delete createBody.payment_method_type;
              delete createBody.payment_method_data;
            }
            const intent = await hs.call("POST", "/payments", key, {
              ...createBody,
              profile_id: profileId,
              confirm: inlineConfirm,
              capture_method: "automatic",
            });
            if (!inlineConfirm)
              expect(intent.status).toBe(
                requestVariant.clientConfirmation
                  ? "requires_payment_method"
                  : "requires_confirmation",
              );
            if (requestVariant.clientConfirmation) {
              expect(typeof account.publishable_key).toBe("string");
              expect(typeof intent.client_secret).toBe("string");
            }
            const paymentId = intent.payment_id;
            const confirmed = inlineConfirm
              ? intent
              : await hs.call("POST", `/payments/${paymentId}/confirm`, key, {
                  ...body,
                  profile_id: profileId,
                  capture_method: "automatic",
                });
            if (!requestVariant.clientConfirmation) {
              expect(confirmed.connector).toBe(connector);
              expect(confirmed.merchant_connector_id).toBe(
                mca.merchant_connector_id,
              );
            }
            expect(confirmed.next_action == null).toBe(true);
            expect(confirmed.mandate_id == null).toBe(true);
            const target = "succeeded";
            expect([target, "processing"]).toContain(confirmed.status);
            const sync = async (expected: string) => {
              await expect
                .poll(
                  async () => {
                    const payment = await hs.call(
                      "GET",
                      `/payments/${paymentId}?force_sync=true`,
                      key,
                    );
                    expect(payment.connector).toBe(connector);
                    expect(payment.merchant_connector_id).toBe(
                      mca.merchant_connector_id,
                    );
                    expect(payment.amount).toBe(body.amount);
                    expect(payment.currency).toBe(body.currency);
                    expect(payment.payment_id).toBe(paymentId);
                    if (payment.status === expected) {
                      expect(payment.amount_capturable).toBe(0);
                      expect(payment.amount_received).toBe(body.amount);
                    }
                    return payment.status;
                  },
                  { intervals: [1000, 3000, 5000], timeout: 90_000 },
                )
                .toBe(expected);
            };
            await sync(target);
            const reference = await assertUcsGateway(
              merchantId,
              paymentId,
              connector,
            );
            const connectedAccount =
              body.split_payments?.stripe_split_payment?.transfer_account_id;
            const processor = await stripePaymentIntent(
              auth,
              reference,
              connectedAccount,
            );
            expect(processor.livemode).toBe(false);
            expect(processor.status).toBe("succeeded");
            expect(processor.amount_received).toBe(body.amount);
            expect(processor.currency).toBe(body.currency.toLowerCase());
            if (body.description)
              expect(processor.description).toBe(body.description);
            if (body.billing_descriptor?.statement_descriptor_suffix)
              expect(processor.statement_descriptor_suffix).toBe(
                body.billing_descriptor.statement_descriptor_suffix,
              );
            for (const [key, value] of Object.entries(body.metadata ?? {}))
              expect(processor.metadata?.[key]).toBe(
                typeof value === "string" ? value : JSON.stringify(value),
              );
            if (body.shipping && !connectedAccount)
              expect(processor.shipping?.address?.line1).toBe(
                body.shipping.address.line1,
              );
            if (connectedAccount)
              expect(processor.application_fee_amount).toBe(
                body.split_payments.stripe_split_payment.application_fees,
              );
            await info.attach("payment-evidence", {
              body: JSON.stringify({
                connector,
                scenario: title,
                gateway: "unified_connector_service",
                processorPaymentCompleted: true,
                fixture: "sandbox",
                requestVariant: requestVariant.id,
              }),
              contentType: "application/json",
            });
          } finally {
            await hs.dispose();
          }
        });
      }
    });
  }
}
