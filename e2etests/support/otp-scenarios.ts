import { randomUUID } from "node:crypto";
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
            assertOtp(body);
            const intent = await hs.call("POST", "/payments", key, {
              ...body,
              profile_id: profileId,
              confirm: false,
              capture_method: "automatic",
            });
            expect(intent.status).toBe("requires_confirmation");
            const paymentId = intent.payment_id;
            const confirmed = await hs.call(
              "POST",
              `/payments/${paymentId}/confirm`,
              key,
              {
                ...body,
                profile_id: profileId,
                capture_method: "automatic",
              },
            );
            expect(confirmed.connector).toBe(connector);
            expect(confirmed.merchant_connector_id).toBe(
              mca.merchant_connector_id,
            );
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
            await assertUcsGateway(merchantId, paymentId, connector);
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
