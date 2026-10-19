import type { RequestVariant } from "../../../support/cases.js";

export const variants: readonly RequestVariant[] = [
  {
    id: "client-capture",
    clientConfirmation: true,
    scenarios: ["manual-capture"],
  },
  { id: "client-void", clientConfirmation: true, scenarios: ["manual-void"] },
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
  { id: "manual-capture", scenarios: ["manual-capture"] },
  { id: "manual-void", scenarios: ["manual-void"] },
];
