import type { RequestVariant } from "../../../support/cases.js";

export const variants: readonly RequestVariant[] = [
  {
    id: "inline-customer",
    payment: {
      confirm: true,
      customer: {
        name: "Test Buyer",
        email: "ucs-e2e@example.com",
        phone: "2025550100",
        phone_country_code: "+1",
      },
      metadata: { fixture_case: "customer" },
      merchant_order_reference_id: "synthetic-order",
    },
    scenarios: ["automatic"],
  },
  { id: "refund-submission", scenarios: ["refund-submission"] },
  { id: "capture-submission", scenarios: ["capture-submission"] },
  { id: "manual-void", scenarios: ["manual-void"] },
];
