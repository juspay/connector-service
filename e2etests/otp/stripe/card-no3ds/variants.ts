import type { RequestVariant } from "../../../support/cases.js";

const checkoutDetails = {
  confirm: true,
  description: "Synthetic checkout",
  merchant_order_reference_id: "synthetic-order",
  payment_channel: "ecommerce",
  customer: {
    name: "Test Buyer",
    email: "ucs-e2e@example.com",
    phone: "2025550100",
    phone_country_code: "+1",
  },
  billing: {
    email: "ucs-e2e@example.com",
    phone: { number: "2025550100", country_code: "+1" },
  },
  shipping: {
    address: {
      first_name: "Test",
      last_name: "Buyer",
      line1: "1 Example Street",
      city: "San Francisco",
      state: "CA",
      zip: "94107",
      country: "US",
    },
  },
  billing_descriptor: { statement_descriptor_suffix: "E2E" },
  metadata: { fixture_case: "checkout", order_reference: "synthetic-order" },
};

export const variants: readonly RequestVariant[] = [
  { id: "client-confirm", clientConfirmation: true, scenarios: ["automatic"] },
  {
    id: "inline-confirm",
    payment: { confirm: true },
    scenarios: ["automatic"],
  },
  {
    id: "checkout-details",
    payment: checkoutDetails,
    scenarios: ["automatic"],
  },
  {
    id: "connect-direct",
    fixture: "stripe-connect",
    payment: {
      ...checkoutDetails,
      split_payments: {
        stripe_split_payment: { charge_type: "direct", application_fees: 300 },
      },
    },
    scenarios: ["automatic"],
  },
  {
    id: "connect-no-shipping",
    fixture: "stripe-connect",
    payment: {
      ...checkoutDetails,
      shipping: null,
      split_payments: {
        stripe_split_payment: { charge_type: "direct", application_fees: 300 },
      },
    },
    scenarios: ["automatic"],
  },
];
