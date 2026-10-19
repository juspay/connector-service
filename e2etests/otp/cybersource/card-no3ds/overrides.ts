import type { ConnectorScenarioConfig } from "../../../support/cases.js";

export const overrides: ConnectorScenarioConfig = {
  cases: {
    baseline: {},
    "inline-customer": {},
    "refund-full": { completion: "submission" },
    "manual-capture": { completion: "submission" },
    "manual-void": {},
  },
};
