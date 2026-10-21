import { randomUUID } from "node:crypto";
import { test, expect, type TestInfo } from "@playwright/test";
import {
  assertOtp,
  loadCredentials,
  loadRunConfig,
  resolveOverrides,
  merge,
  type Json,
} from "./config.js";
import {
  Hyperswitch,
  readUcsGateway,
  readConnectorRefundReference,
} from "./hs.js";
import type { Connector, OtpScenario } from "./cases.js";
import {
  equal,
  oneOf,
  assertChecks,
  recordChecks,
  verifyChecks,
  type Checks,
} from "./checks.js";
import { reportScenario, reportSummary } from "./report.js";
import { processorAdapters } from "./processors/index.js";
export async function runOtpScenario(
  connector: Connector,
  requestVariant: OtpScenario,
  info: TestInfo,
) {
  const runConfig = loadRunConfig(connector);
  const overrides = resolveOverrides(
    runConfig.document,
    connector,
    requestVariant,
  );
  const variant = requestVariant.scenarios[0];
  const title = variant;
  await reportScenario(info, requestVariant);
  const admin = process.env.HS_ADMIN_API_KEY ?? "test_admin";
  const auth = loadCredentials(connector, runConfig.credential);
  const processorAdapter = processorAdapters[connector];
  processorAdapter?.validateCredentials(auth);
  const merchantId = `e2e_${randomUUID().replaceAll("-", "")}`;
  const hs = await Hyperswitch.create(info);
  try {
    const { account, key, profileId, mca } =
      await test.step("Prepare sandbox merchant and routing", async () => {
        await hs.enableUcs(admin);
        const account = await hs.call("POST", "/accounts", admin, {
          merchant_name: "UCS Playwright OTP",
          primary_business_details: [{ country: "US", business: "default" }],
          merchant_id: merchantId,
        });
        const apiKey = await hs.call("POST", `/api_keys/${merchantId}`, admin, {
          name: "UCS E2E",
          expiration: new Date(Date.now() + 86_400_000).toISOString(),
          description: "Disposable sandbox e2e test key",
        });
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
            metadata: merge(auth.metadata ?? {}, overrides.connectorMetadata),
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
        return { account, key, profileId, mca };
      });
    const createRequest = merge(requestVariant.request, overrides.payment);
    const body = requestVariant.confirmRequest
      ? merge(createRequest, requestVariant.confirmRequest)
      : createRequest;
    if (requestVariant.fixture === "merchant-reference") {
      body.payment_id = `synthetic_${randomUUID().replaceAll("-", "")}`;
      body.merchant_order_reference_id = `order_${randomUUID().replaceAll("-", "")}`;
    }
    if (
      requestVariant.fixture &&
      requestVariant.fixture !== "merchant-reference"
    ) {
      if (!processorAdapter?.prepareFixture)
        throw new Error("No processor adapter can prepare this fixture");
      await processorAdapter.prepareFixture(auth, body, requestVariant.fixture);
    }
    assertOtp({
      ...body,
      authentication_type: body.authentication_type ?? "no_three_ds",
    });
    const inlineConfirm = createRequest.confirm === true;
    const manual = [
      "manual-capture",
      "manual-void",
      "capture-submission",
      "void-submission",
    ].includes(variant);
    const captureMethod = manual ? "manual" : "automatic";
    const createBody = structuredClone(createRequest);
    if (requestVariant.clientConfirmation) {
      delete createBody.payment_method;
      delete createBody.payment_method_type;
      delete createBody.payment_method_data;
    }
    const intent = await hs.call("POST", "/payments", key, {
      ...createBody,
      profile_id: profileId,
      confirm: inlineConfirm,
      capture_method: captureMethod,
    });
    const paymentId = intent.payment_id;
    await verifyChecks(info, "Payment creation checks", {
      ...(!inlineConfirm
        ? {
            status: equal(
              requestVariant.clientConfirmation
                ? "requires_payment_method"
                : "requires_confirmation",
              intent.status,
            ),
          }
        : {}),
      payment_id_recorded: equal(
        true,
        typeof paymentId === "string" && paymentId.length > 0,
      ),
      ...(requestVariant.clientConfirmation
        ? {
            publishable_key_available: equal(
              true,
              typeof account.publishable_key === "string",
            ),
            client_secret_available: equal(
              true,
              typeof intent.client_secret === "string",
            ),
          }
        : {}),
      ...(requestVariant.fixture === "merchant-reference"
        ? {
            supplied_payment_reference_matches: equal(
              true,
              paymentId === body.payment_id,
            ),
            order_reference_matches: equal(
              true,
              intent.merchant_order_reference_id ===
                body.merchant_order_reference_id,
            ),
          }
        : {}),
    });
    const confirmed = inlineConfirm
      ? intent
      : await hs.call(
          "POST",
          `/payments/${paymentId}/confirm`,
          requestVariant.clientConfirmation ? account.publishable_key : key,
          {
            ...(requestVariant.confirmRequest ?? body),
            ...(requestVariant.clientConfirmation
              ? { client_secret: intent.client_secret }
              : {}),
            profile_id: profileId,
            capture_method: captureMethod,
          },
        );
    const initialTarget = manual ? "requires_capture" : "succeeded";
    let target = initialTarget;
    await verifyChecks(info, "Payment confirmation checks", {
      ...(!requestVariant.clientConfirmation
        ? {
            connector: equal(connector, confirmed.connector),
            connector_account_matches: equal(
              true,
              confirmed.merchant_connector_id === mca.merchant_connector_id,
            ),
          }
        : {}),
      customer_action_required: equal(false, confirmed.next_action != null),
      mandate_created: equal(false, confirmed.mandate_id != null),
      status: oneOf([initialTarget, "processing"], confirmed.status),
    });
    const paymentChecks = (payment: Json, expected: string): Checks => ({
      connector: equal(connector, payment.connector),
      authentication_type: equal("no_three_ds", payment.authentication_type),
      setup_future_usage: equal(null, payment.setup_future_usage ?? null),
      mandate_created: equal(false, payment.mandate_id != null),
      connector_account_matches: equal(
        true,
        payment.merchant_connector_id === mca.merchant_connector_id,
      ),
      payment_id_matches: equal(true, payment.payment_id === paymentId),
      amount: equal(body.amount, payment.amount),
      currency: equal(body.currency, payment.currency),
      ...(payment.status === expected
        ? {
            amount_capturable: equal(
              expected === "requires_capture" ? body.amount : 0,
              payment.amount_capturable,
            ),
            ...(expected === "succeeded"
              ? { amount_received: equal(body.amount, payment.amount_received) }
              : {}),
          }
        : {}),
    });
    const sync = async (expected: string) =>
      test.step(`Verify payment status: ${expected}`, async () => {
        let actual: string | undefined;
        let checks: Checks | undefined;
        try {
          await expect
            .poll(
              async () => {
                const payment = await hs.call(
                  "GET",
                  `/payments/${paymentId}?force_sync=true`,
                  key,
                );
                actual = payment.status;
                checks = paymentChecks(payment, expected);
                assertChecks(checks, "Payment field checks");
                return payment.status;
              },
              {
                intervals: [1000, 3000, 5000],
                timeout: 90_000,
                message: `Verify payment status: expected ${expected}`,
              },
            )
            .toBe(expected);
        } finally {
          if (checks) await recordChecks(info, "Payment field checks", checks);
          await recordChecks(
            info,
            `Payment status: expected ${expected}, actual ${actual ?? "unavailable"}`,
            { status: equal(expected, actual) },
          );
        }
      });
    await sync(initialTarget);
    let attemptStatus = "charged";
    if (variant === "manual-capture" || variant === "capture-submission") {
      const captured = await hs.call(
        "POST",
        `/payments/${paymentId}/capture`,
        key,
        { amount_to_capture: body.amount },
      );
      await verifyChecks(info, "Capture response check", {
        status: oneOf(["succeeded", "processing"], captured.status),
      });
      target = captured.status;
      if (variant === "capture-submission")
        attemptStatus = target === "succeeded" ? "charged" : "pending";
      else {
        target = "succeeded";
        await sync(target);
      }
    } else if (variant === "manual-void" || variant === "void-submission") {
      const cancelled = await hs.call(
        "POST",
        `/payments/${paymentId}/cancel`,
        key,
        { cancellation_reason: "requested_by_customer" },
      );
      await verifyChecks(info, "Cancellation response check", {
        status: oneOf(["cancelled", "processing"], cancelled.status),
      });
      target = cancelled.status;
      attemptStatus = target === "cancelled" ? "voided" : "pending";
      if (variant !== "void-submission") {
        target = "cancelled";
        attemptStatus = "voided";
        await sync(target);
      }
    }
    let refundedAmount: number | undefined;
    if (
      ["refund-full", "refund-partial", "refund-submission"].includes(variant)
    ) {
      refundedAmount =
        variant === "refund-partial"
          ? Math.floor(body.amount / 2)
          : body.amount;
      await test.step(
        variant === "refund-submission"
          ? "Verify refund submission"
          : "Verify refund status: succeeded",
        async () => {
          const refund = await hs.call("POST", "/refunds", key, {
            payment_id: paymentId,
            amount: refundedAmount,
          });
          let observedRefund = refund;
          const refundChecks = (value: Json, terminal: boolean): Checks => ({
            status: terminal
              ? equal("succeeded", value.status)
              : oneOf(["pending", "succeeded"], value.status),
            amount: equal(refundedAmount!, value.amount),
            payment_id_matches: equal(true, value.payment_id === paymentId),
            ...(terminal
              ? { currency: equal(body.currency, value.currency) }
              : {}),
          });
          await verifyChecks(info, "Refund response checks", {
            ...refundChecks(refund, false),
            refund_id_recorded: equal(
              true,
              typeof refund.refund_id === "string" &&
                refund.refund_id.length > 0,
            ),
          });
          try {
            if (variant !== "refund-submission")
              await expect
                .poll(
                  async () => {
                    observedRefund = await hs.call(
                      "GET",
                      `/refunds/${refund.refund_id}?force_sync=true`,
                      key,
                    );
                    assertChecks(
                      {
                        amount: equal(refundedAmount!, observedRefund.amount),
                        payment_id_matches: equal(
                          true,
                          observedRefund.payment_id === paymentId,
                        ),
                        currency: equal(body.currency, observedRefund.currency),
                      },
                      "Refund fields",
                    );
                    return observedRefund.status;
                  },
                  { intervals: [1000, 3000, 5000], timeout: 90_000 },
                )
                .toBe("succeeded");
          } finally {
            await recordChecks(
              info,
              "Refund checks",
              refundChecks(observedRefund, variant !== "refund-submission"),
            );
          }
          await verifyChecks(info, "Refund routing checks", {
            processor_reference_recorded: equal(
              true,
              await readConnectorRefundReference(
                merchantId,
                refund.refund_id,
                connector,
              ),
            ),
          });
        },
      );
    }
    const reference =
      await test.step("Verify UCS routing and processor reference", async () => {
        const result = await readUcsGateway(
          merchantId,
          paymentId,
          connector,
          attemptStatus,
        );
        await verifyChecks(info, "UCS routing checks", {
          gateway: equal("unified_connector_service", result.gateway),
          processor_outcome_recorded: equal(
            true,
            result.processorOutcomeVerified,
          ),
        });
        return result.processorReference;
      });
    if (processorAdapter)
      await test.step(`Verify payment in ${processorAdapter.label} sandbox`, async () => {
        const checks = await processorAdapter.verify({
          auth,
          payment: body,
          reference,
          outcome: target,
          refundedAmount,
          profile: overrides.profile,
        });
        await verifyChecks(info, `${processorAdapter.label} checks`, checks);
      });
    await reportSummary(info, {
      connector,
      scenario: title,
      outcome: variant.endsWith("submission")
        ? "submission-accepted"
        : refundedAmount !== undefined
          ? "refund-succeeded"
          : target,
      verification: variant.endsWith("submission")
        ? "submission-only"
        : "terminal",
      requestVariant: requestVariant.id,
    });
  } finally {
    await hs.dispose();
  }
}
