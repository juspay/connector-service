import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
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
