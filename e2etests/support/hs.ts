import {
  request,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import pg from "pg";
import type { Json } from "./config.js";

export class Hyperswitch {
  private constructor(private api: APIRequestContext) {}

  static async create() {
    return new Hyperswitch(
      await request.newContext({
        baseURL: process.env.HS_BASE_URL ?? "http://localhost:8080",
        timeout: 60_000,
      }),
    );
  }

  async call(
    method: string,
    path: string,
    key: string,
    data?: Json,
  ): Promise<Json> {
    const response = await this.fetch(method, path, key, data);
    if (!response.ok()) {
      // Never include raw response bodies or keys in test output.
      throw new Error(
        `${method} ${path}: HTTP ${response.status()}, request-id=${response.headers()["x-request-id"] ?? "unknown"}`,
      );
    }
    return response.json();
  }

  private async fetch(
    method: string,
    path: string,
    key: string,
    data?: Json,
  ): Promise<APIResponse> {
    try {
      return await this.api.fetch(path, {
        method,
        headers: { "api-key": key },
        data,
      });
    } catch {
      // Playwright transport errors can include a request log with credential headers.
      throw new Error(`${method} ${path}: HS transport failed`);
    }
  }

  async enableUcs(admin: string) {
    const existing = await this.fetch("GET", "/configs/ucs_enabled", admin);
    if (existing.ok()) {
      if ((await existing.json()).value !== "true") {
        throw new Error(
          "HS ucs_enabled must be true. Enable it on the dedicated test HS before running.",
        );
      }
    } else if (existing.status() === 404) {
      await this.call("POST", "/configs/", admin, {
        key: "ucs_enabled",
        value: "true",
      });
    } else {
      throw new Error(
        `Cannot read HS UCS configuration: HTTP ${existing.status()}`,
      );
    }
  }

  async dispose() {
    await this.api.dispose();
  }
}

// Checking the recorded gateway prevents a green run through HS's native connectors.
export async function assertUcsGateway(
  merchantId: string,
  paymentId: string,
  connector: string,
  attemptStatus = "charged",
) {
  const client = new pg.Client({
    connectionString:
      process.env.HS_DATABASE_URL ??
      `postgresql://db_user:db_pass@127.0.0.1:${process.env.HS_DB_PORT ?? "15432"}/hyperswitch_db`,
    connectionTimeoutMillis: 10_000,
  });
  await client.connect();
  try {
    const result = await client.query(
      `SELECT p.feature_metadata->>'gateway_system' AS gateway,
        (SELECT a.connector_transaction_id FROM payment_attempt a
          WHERE a.merchant_id=p.merchant_id AND a.payment_id=p.payment_id
            AND a.connector=$3 AND a.status::text=$4 ORDER BY a.created_at DESC LIMIT 1) AS processor_reference,
        EXISTS (SELECT 1 FROM payment_attempt a
          WHERE a.merchant_id=p.merchant_id AND a.payment_id=p.payment_id
            AND a.connector=$3 AND a.status::text=$4
            AND a.connector_transaction_id IS NOT NULL
            AND a.connector_transaction_id <> '') AS processor_payment_completed
       FROM payment_intent p WHERE p.merchant_id=$1 AND p.payment_id=$2`,
      [merchantId, paymentId, connector, attemptStatus],
    );
    if (result.rows[0]?.gateway !== "unified_connector_service") {
      throw new Error(
        `Payment ${paymentId} did not record unified_connector_service as its gateway`,
      );
    }
    if (!result.rows[0]?.processor_payment_completed) {
      throw new Error(
        "Payment did not record the expected connector outcome with a processor reference",
      );
    }
    return result.rows[0].processor_reference as string;
  } finally {
    await client.end();
  }
}

export async function assertConnectorRefund(
  merchantId: string,
  refundId: string,
  connector: string,
) {
  const client = new pg.Client({
    connectionString:
      process.env.HS_DATABASE_URL ??
      `postgresql://db_user:db_pass@127.0.0.1:${process.env.HS_DB_PORT ?? "15432"}/hyperswitch_db`,
    connectionTimeoutMillis: 10_000,
  });
  await client.connect();
  try {
    const result = await client.query(
      "SELECT connector_refund_id IS NOT NULL AND connector_refund_id <> '' AS processor_reference FROM refund WHERE merchant_id=$1 AND refund_id=$2 AND connector=$3",
      [merchantId, refundId, connector],
    );
    if (!result.rows[0]?.processor_reference)
      throw new Error("Refund did not record a processor reference");
  } finally {
    await client.end();
  }
}
