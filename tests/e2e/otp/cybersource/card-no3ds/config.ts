import type { ConnectorScenarioConfig } from "../../../framework/scenario.js";
import { basicCardPayment } from "../../superset/card-no3ds/requests.js";

export const config: ConnectorScenarioConfig = {
  overrides: {
    "client-confirm": {
      // Cybersource requires email and a billing address for card authorization.
      payment: {
        email: "ucs-e2e@example.com",
        billing: basicCardPayment().billing,
      },
    },
    "client-capture": { completion: "submission" },
    "refund-partial": { completion: "submission" },
    "refund-full": { completion: "submission" },
    "manual-capture": { completion: "submission" },
  },
};
