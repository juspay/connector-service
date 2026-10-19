import type { Json } from "./config.js";

export const connectors = ["stripe"] as const;
export type Connector = (typeof connectors)[number];
export const scenarios = ["automatic"] as const;
export type Scenario = (typeof scenarios)[number];
export type RequestVariant = {
  id: string;
  fixture?: "stripe-connect";
  clientConfirmation?: boolean;
  payment?: Json;
  connectorMetadata?: Json;
  profile?: Json;
  scenarios: readonly Scenario[];
};

// Baseline exercises the automatic payment. Additional variants can describe
// distinct request/configuration behavior without duplicating connector setup.
export function paymentCases(
  variants: readonly RequestVariant[],
  selected?: string,
) {
  const all: RequestVariant[] = [{ id: "baseline", scenarios }, ...variants];
  const ids = new Set<string>();
  for (const variant of all) {
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(variant.id) || ids.has(variant.id)) {
      throw new Error("Request variants require unique synthetic identifiers");
    }
    ids.add(variant.id);
    if (
      !variant.scenarios.length ||
      new Set(variant.scenarios).size !== variant.scenarios.length ||
      variant.scenarios.some((s) => !scenarios.includes(s))
    ) {
      throw new Error(`Invalid lifecycle selection for ${variant.id}`);
    }
  }
  if (selected && !ids.has(selected))
    throw new Error(`Unknown request variant: ${selected}`);
  return all.filter((v) => !selected || v.id === selected);
}
