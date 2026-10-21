import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";
import { connectDirectPayment, connectDetailedPayment } from "./requests.js";

export const overrides: ConnectorScenarioConfig = {
  cases: {
    baseline: {},
    "billing-profile": {},
    "refund-full": {},
    "refund-partial": {},
    "manual-capture": {},
    "manual-void": {},
    "client-confirm": {},
    "inline-confirm": {},
    "checkout-details": {},
    "direct-charge": {
      request: connectDirectPayment(),
    },
    "direct-charge-details": {
      request: connectDetailedPayment(),
    },
    "direct-charge-no-shipping": {
      request: { ...connectDirectPayment(), shipping: null },
    },
  },
};
