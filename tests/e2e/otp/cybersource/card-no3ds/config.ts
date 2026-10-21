import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  overrides: {
    "client-confirm": { payment: { email: "ucs-e2e@example.com" } },
    "client-capture": { completion: "submission" },
    "refund-partial": { completion: "submission" },
    "refund-full": { completion: "submission" },
    "manual-capture": { completion: "submission" },
  },
};
