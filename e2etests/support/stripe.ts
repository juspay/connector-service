import type { Json } from "./config.js";

export function assertStripeSandboxKey(auth: Json): string {
  const key = auth.connector_account_details?.api_key;
  if (typeof key !== "string" || !/^(sk|rk)_test_/.test(key))
    throw new Error("Stripe tests require a sandbox API key");
  return key;
}

async function stripeRead(
  auth: Json,
  path: string,
  account?: string,
): Promise<Json> {
  const key = assertStripeSandboxKey(auth);
  const headers: Record<string, string> = { Authorization: `Bearer ${key}` };
  if (account) headers["Stripe-Account"] = account;
  let response: Response;
  try {
    response = await fetch(`https://api.stripe.com/v1/${path}`, {
      headers,
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new Error("Stripe sandbox verification transport failed");
  }
  if (!response.ok)
    throw new Error(`Stripe sandbox read failed: HTTP ${response.status}`);
  try {
    return await response.json();
  } catch {
    throw new Error("Invalid Stripe sandbox fixture response");
  }
}

// Connected account identifiers stay in runtime fixtures, never in committed data.
export async function stripeConnectedAccount(auth: Json, selected?: string) {
  assertStripeSandboxKey(auth);
  const account = selected ?? process.env.STRIPE_CONNECTED_ACCOUNT_ID;
  if (account && !/^acct_[A-Za-z0-9]+$/.test(account))
    throw new Error("Invalid sandbox connected account identifier");
  const data = await stripeRead(
    auth,
    account ? `accounts/${encodeURIComponent(account)}` : "accounts?limit=100",
  );
  const candidates: Json[] = account ? [data] : (data.data ?? []);
  const eligible = candidates.find(
    (a) =>
      a.charges_enabled === true &&
      a.capabilities?.card_payments === "active" &&
      /^acct_[A-Za-z0-9]+$/.test(a.id),
  );
  if (!eligible)
    throw new Error(
      "No charge-enabled sandbox Connect account; configure STRIPE_CONNECTED_ACCOUNT_ID",
    );
  return eligible.id as string;
}

export async function stripePaymentIntent(
  auth: Json,
  reference: string,
  account?: string,
) {
  if (!/^pi_[A-Za-z0-9]+$/.test(reference))
    throw new Error("Stripe payment has no PaymentIntent reference");
  return stripeRead(
    auth,
    `payment_intents/${encodeURIComponent(reference)}`,
    account,
  );
}

export async function stripeCharge(
  auth: Json,
  reference: string,
  account?: string,
) {
  if (!/^ch_[A-Za-z0-9]+$/.test(reference))
    throw new Error("Stripe payment has no charge reference");
  return stripeRead(auth, `charges/${encodeURIComponent(reference)}`, account);
}

export async function stripePaymentMethod(
  auth: Json,
  reference: string,
  account?: string,
) {
  if (!/^pm_[A-Za-z0-9]+$/.test(reference))
    throw new Error("Stripe payment has no PaymentMethod reference");
  return stripeRead(
    auth,
    `payment_methods/${encodeURIComponent(reference)}`,
    account,
  );
}
