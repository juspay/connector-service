import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  overrides: {
    "client-capture": { completion: "submission" },
    "refund-partial": { completion: "submission" },
    "refund-full": { completion: "submission" },
    "manual-capture": { completion: "submission" },
  },
};
