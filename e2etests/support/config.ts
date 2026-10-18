import type { Connector, RequestVariant } from "./cases.js";
import { readFileSync } from "node:fs";

export type Json = Record<string, any>;
export type Overrides = {
  connectorMetadata?: Json;
  profile?: Json;
  payment?: Json;
};

export function merge<T extends Json>(base: T, patch: Json = {}): T {
  const result: Json = structuredClone(base);
  for (const [key, value] of Object.entries(patch)) {
    if (["__proto__", "constructor", "prototype"].includes(key))
      throw new Error("Invalid override key");
    result[key] =
      value && typeof value === "object" && !Array.isArray(value)
        ? merge(
            result[key] && typeof result[key] === "object" ? result[key] : {},
            value,
          )
        : structuredClone(value);
  }
  return result as T;
}

export function credentials(
  document: Json,
  connector: string,
  selected?: string,
): Json {
  const entry = document[connector];
  const value = selected
    ? entry?.[selected]
    : entry?.connector_account_details
      ? entry
      : Object.values(entry ?? {}).find(
          (item: any) => item?.connector_account_details,
        );
  if (!value?.connector_account_details) {
    throw new Error(
      `Missing HS sandbox credentials for ${connector}${selected ? "/" + selected : ""}`,
    );
  }
  return structuredClone(value);
}

export function readPrivateJson(path: string, label: string): Json {
  try {
    const document = JSON.parse(readFileSync(path, "utf8"));
    if (!document || typeof document !== "object" || Array.isArray(document))
      throw new Error();
    return document;
  } catch {
    // JSON parse errors can quote credential contents. Keep paths and raw input private.
    throw new Error(
      `Cannot read ${label}; check the file exists and contains a JSON object`,
    );
  }
}

export function loadCredentials(connector: Connector, selected?: string): Json {
  const path =
    process.env.CONNECTOR_AUTH_FILE_PATH ??
    process.env.CYPRESS_CONNECTOR_AUTH_FILE_PATH;
  if (!path)
    throw new Error(
      "Set CONNECTOR_AUTH_FILE_PATH to the decrypted HS main creds.json",
    );
  return credentials(
    readPrivateJson(path, "sandbox credentials"),
    connector,
    selected,
  );
}

export function resolveOverrides(
  document: Json,
  connector: Connector,
  variant: RequestVariant,
): Overrides {
  if (
    Object.keys(document).some((k) => !["connectors", "variants"].includes(k))
  ) {
    throw new Error(
      "Override files support connectors and variants only; remove legacy merchant profiles",
    );
  }
  const connectorPatch = document.connectors?.[connector] ?? {};
  const variantPatch = document.variants?.[`${connector}/${variant.id}`] ?? {};
  // Credentials always come from our connector sandbox account. Variant patches
  // can describe request shapes, but cannot select a different account.
  const allowed = ["payment", "profile", "connectorMetadata"];
  for (const [patch, extra] of [
    [connectorPatch, ["credential"]],
    [variantPatch, []],
  ] as const) {
    if (
      Object.keys(patch).some(
        (k) =>
          !allowed.includes(k) && !(extra as readonly string[]).includes(k),
      )
    ) {
      throw new Error(
        "Overrides accept only payment, profile, connectorMetadata; credential belongs to connector settings",
      );
    }
  }
  const { credential: _credential, ...common } = connectorPatch;
  const { id: _id, scenarios: _scenarios, ...builtin } = variant;
  return merge(merge(common, builtin), variantPatch);
}

export function loadRunConfig(connector: Connector) {
  const path = process.env.E2E_OVERRIDES_FILE;
  const document: Json = path ? readPrivateJson(path, "sandbox overrides") : {};
  return {
    document,
    credential: document.connectors?.[connector]?.credential as
      string | undefined,
  };
}

export function assertOtp(body: Json): void {
  if (
    body.authentication_type !== "no_three_ds" ||
    body.payment_method !== "card" ||
    body.off_session === true ||
    body.setup_future_usage != null ||
    body.customer_acceptance != null ||
    body.mandate_data != null ||
    body.mandate_id != null ||
    body.recurring_details != null ||
    !body.payment_method_data?.card ||
    !Number.isSafeInteger(body.amount) ||
    body.amount <= 0
  ) {
    throw new Error(
      "OTP requires a positive amount, fresh card, No3DS, and no mandate/setup fields",
    );
  }
}
