import type { ConnectorScenarioConfig } from "../../../support/cases.js";
import { connectDirectPayment, connectDetailedPayment } from "./fixtures.js";

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
      fixture: "stripe-connect",
      coverage: "reference-pattern",
    },
    "direct-charge-details": {
      request: connectDetailedPayment(),
      fixture: "stripe-connect",
      coverage: "reference-pattern",
    },
    "direct-charge-no-shipping": {
      request: { ...connectDirectPayment(), shipping: null },
      fixture: "stripe-connect",
    },
  },
};
