import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  cases: {
    baseline: {},
    "inline-customer": {},
    "refund-full": { completion: "submission" },
    "manual-capture": { completion: "submission" },
    "manual-void": {},
  },
};
