import type { Checks } from "../checks.js";
import type { Json } from "../config.js";
import type { OtpScenario } from "../cases.js";

export type ProcessorContext = {
  auth: Json;
  payment: Json;
  reference: string;
  outcome: string;
  refundedAmount?: number;
  profile?: Json;
};

// Adapters read processor state and return standard checks. They never assert or format reports.
export type ProcessorAdapter = {
  label: string;
  validateCredentials(auth: Json): void;
  prepareFixture?(
    auth: Json,
    payment: Json,
    fixture: OtpScenario["fixture"],
  ): Promise<void>;
  verify(context: ProcessorContext): Promise<Checks>;
};
