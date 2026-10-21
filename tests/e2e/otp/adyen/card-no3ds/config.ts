import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  payment: {
    payment_method_data: {
      card: { card_number: "4111111111111111", card_cvc: "737" },
    },
  },
  overrides: {
    // Adyen maps line1 to houseNumberOrName and line2 to street.
    "billing-profile": {
      payment: {
        shipping: { address: { line1: "1", line2: "Example Street" } },
      },
    },
    "checkout-details": {
      payment: {
        shipping: { address: { line1: "1", line2: "Example Street" } },
      },
    },
    "client-void": { completion: "submission" },
    "client-capture": { completion: "submission" },
    "refund-partial": { completion: "submission" },
    "manual-capture": { completion: "submission" },
    "manual-void": { completion: "submission" },
    "refund-full": { completion: "submission" },
    "inline-consent": {
      payment: { currency: "AUD" },
      fixture: "merchant-reference",
    },
    "inline-currency": ["EUR", "GBP", "CHF", "SGD"].map((currency) => ({
      id: `inline-${currency.toLowerCase()}`,
      payment: { currency },
    })),
  },
};
