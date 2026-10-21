import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";

export const config: ConnectorScenarioConfig = {
  exclude: {
    "refund-full":
      "Refunds require a settled payment; these scenarios create a fresh payment.",
    "refund-partial":
      "Refunds require a settled payment; these scenarios create a fresh payment.",
  },
  payment: {
    payment_method_data: { card: { card_number: "4111111111111111" } },
  },
};
