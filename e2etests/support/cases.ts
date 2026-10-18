import type { Json } from "./config.js";

export const connectors = [
  "adyen",
  "cybersource",
  "stripe",
  "paypal",
  "authorizedotnet",
  "checkout",
] as const;
export type Connector = (typeof connectors)[number];
export const scenarios = [
  "automatic",
  "manual-capture",
  "manual-void",
  "automatic-refund",
] as const;
export type Scenario = (typeof scenarios)[number];
export type RequestVariant = {
  id: string;
  payment?: Json;
  connectorMetadata?: Json;
  profile?: Json;
  scenarios: readonly Scenario[];
};

// Baseline exercises each lifecycle once. Additional variants should target only
// the lifecycle needed to verify their distinct request/configuration behavior.
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

export function refundVerification(
  connector: Connector,
): "accepted" | "synced" {
  // Adyen has no UCS RSync implementation. Test refund submission explicitly;
  // completion via webhook is a separate coverage gap, never a claimed RSync pass.
  return connector === "adyen" ? "accepted" : "synced";
}
