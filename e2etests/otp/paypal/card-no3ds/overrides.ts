import type { ConnectorScenarioConfig } from "../../../support/cases.js";

export const overrides: ConnectorScenarioConfig = {
  payment: {
    payment_method_data: { card: { card_number: "4012000033330026" } },
  },
  cases: {
    baseline: {},
    "refund-full": {},
    "refund-partial": {},
    "client-capture": [
      { id: "client-capture" },
      ...["CAD", "GBP", "AUD"].map((currency) => ({
        id: `client-capture-${currency.toLowerCase()}`,
        payment: { currency },
      })),
    ],
    "client-void": {},
  },
};
