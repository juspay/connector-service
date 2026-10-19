import type { ConnectorScenarioConfig } from "../../../support/cases.js";

export const overrides: ConnectorScenarioConfig = {
  payment: {
    payment_method_data: { card: { card_number: "4111111111111111" } },
  },
  cases: {
    baseline: {},
    "client-capture": {},
    "client-void": {},
    "inline-customer": {},
    "manual-capture": {},
    "manual-void": {},
  },
};
