import { equal, type Checks } from "../checks.js";
import {
  assertStripeSandboxKey,
  stripeConnectedAccount,
  stripePaymentIntent,
  stripeCharge,
  stripePaymentMethod,
} from "./stripe-api.js";
import type { ProcessorAdapter } from "./types.js";

export const stripeAdapter: ProcessorAdapter = {
  label: "Stripe",
  validateCredentials(auth) {
    assertStripeSandboxKey(auth);
  },
  async prepareFixture(auth, payment, fixture) {
    if (fixture === "stripe-connect") {
      payment.split_payments.stripe_split_payment.transfer_account_id =
        await stripeConnectedAccount(
          auth,
          payment.split_payments.stripe_split_payment.transfer_account_id,
        );
    }
  },
  async verify({ auth, payment, reference, outcome, refundedAmount, profile }) {
    const connectedAccount =
      payment.split_payments?.stripe_split_payment?.transfer_account_id;
    const processor = await stripePaymentIntent(
      auth,
      reference,
      connectedAccount,
    );
    const checks: Record<string, Checks[string]> = {
      livemode: equal(false, processor.livemode),
      status: equal(
        outcome === "cancelled" ? "canceled" : "succeeded",
        processor.status,
      ),
      amount_received: equal(
        outcome === "cancelled" ? 0 : payment.amount,
        processor.amount_received,
      ),
      currency: equal(payment.currency.toLowerCase(), processor.currency),
    };
    if (refundedAmount !== undefined) {
      const chargeId =
        typeof processor.latest_charge === "string"
          ? processor.latest_charge
          : processor.latest_charge?.id;
      const charge = await stripeCharge(auth, chargeId, connectedAccount);
      checks.amount_refunded = equal(refundedAmount, charge.amount_refunded);
      checks.fully_refunded = equal(
        refundedAmount === payment.amount,
        charge.refunded,
      );
    }
    if (profile?.use_billing_as_payment_method_billing === true) {
      const methodId =
        typeof processor.payment_method === "string"
          ? processor.payment_method
          : processor.payment_method?.id;
      const method = await stripePaymentMethod(
        auth,
        methodId,
        connectedAccount,
      );
      checks.billing_address_matches_request = equal(
        true,
        method.billing_details?.address?.line1 ===
          payment.billing.address.line1,
      );
    }
    if (payment.description)
      checks.description_matches_request = equal(
        true,
        processor.description === payment.description,
      );
    if (payment.billing_descriptor?.statement_descriptor_suffix)
      checks.descriptor_matches_request = equal(
        true,
        processor.statement_descriptor_suffix ===
          payment.billing_descriptor.statement_descriptor_suffix,
      );
    if (payment.metadata)
      checks.metadata_matches_request = equal(
        true,
        Object.entries(payment.metadata).every(
          ([key, value]) =>
            processor.metadata?.[key] ===
            (typeof value === "string" ? value : JSON.stringify(value)),
        ),
      );
    if (payment.shipping && !connectedAccount)
      checks.shipping_address_matches_request = equal(
        true,
        processor.shipping?.address?.line1 === payment.shipping.address.line1,
      );
    if (connectedAccount)
      checks.application_fee_amount = equal(
        payment.split_payments.stripe_split_payment.application_fees,
        processor.application_fee_amount,
      );
    return checks;
  },
};
