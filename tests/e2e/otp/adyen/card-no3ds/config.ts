import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const overrides: ConnectorScenarioConfig = {
  payment: {
    payment_method_data: {
      card: { card_number: "4111111111111111", card_cvc: "737" },
    },
  },
  cases: {
    baseline: {},
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
