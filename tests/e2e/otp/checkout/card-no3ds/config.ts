import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const overrides: ConnectorScenarioConfig = {
  cases: {
    baseline: {},
    "inline-customer": {},
    "refund-full": {},
    "refund-partial": {},
    "manual-capture": {},
    "manual-void": {},
  },
};
