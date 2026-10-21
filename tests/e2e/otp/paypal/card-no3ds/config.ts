import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  payment: {
    payment_method_data: { card: { card_number: "4012000033330026" } },
  },
  overrides: {
    "client-capture": [
      { id: "client-capture" },
      ...["CAD", "GBP", "AUD"].map((currency) => ({
        id: `client-capture-${currency.toLowerCase()}`,
        payment: { currency },
      })),
    ],
  },
};
