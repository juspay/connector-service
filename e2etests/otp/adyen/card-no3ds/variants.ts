import type { RequestVariant } from "../../../support/cases.js";

export const variants: readonly RequestVariant[] = [
  { id: "capture-submission", scenarios: ["capture-submission"] },
  { id: "void-submission", scenarios: ["void-submission"] },
  { id: "refund-submission", scenarios: ["refund-submission"] },
  {
    id: "inline-consent-aud",
    fixture: "merchant-reference",
    payment: {
      confirm: true,
      currency: "AUD",
      customer: { name: "Test Buyer", email: "ucs-e2e@example.com" },
      customer_acceptance: {
        acceptance_type: "online",
        online: {
          ip_address: "192.0.2.1",
          user_agent: "Synthetic test browser",
        },
      },
      metadata: { fixture_case: "inline-consent" },
    },
    scenarios: ["automatic"],
  },
  ...["EUR", "GBP", "CHF", "SGD"].map((currency) => ({
    id: `inline-${currency.toLowerCase()}`,
    payment: {
      confirm: true,
      currency,
      metadata: { fixture_case: "currency" },
    },
    scenarios: ["automatic"] as const,
  })),
];
