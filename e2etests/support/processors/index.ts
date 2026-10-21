import type { Connector } from "../cases.js";
import type { ProcessorAdapter } from "./types.js";
import { stripeAdapter } from "./stripe.js";

// Readback is optional and explicit. HS/UCS outcome checks apply to every connector.
export const processorAdapters: Partial<Record<Connector, ProcessorAdapter>> = {
  stripe: stripeAdapter,
};
