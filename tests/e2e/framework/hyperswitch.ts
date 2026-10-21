import {
  request,
  test,
  type TestInfo,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import pg from "pg";
import type { Json } from "./config.js";
import { collectAudit, createDockerLogReader } from "./audit.js";

function apiStepName(method: string, path: string): string {
  const route = path.split("?")[0];
  if (method === "POST" && route === "/payments") return "Create payment";
  if (method === "GET" && route.startsWith("/payments/"))
    return "Retrieve payment";
  if (method === "POST" && route.startsWith("/payments/")) {
    if (route.endsWith("/confirm")) return "Confirm payment";
    if (route.endsWith("/capture")) return "Capture payment";
    if (route.endsWith("/cancel")) return "Cancel payment";
  }
  if (method === "POST" && route === "/refunds") return "Create refund";
  if (method === "GET" && route.startsWith("/refunds/"))
    return "Retrieve refund";
  return `${method} ${route}`;
}

export class Hyperswitch {
  private readonly readAuditLogs = createDockerLogReader();

  private constructor(
    private api: APIRequestContext,
    private report?: TestInfo,
  ) {}

  static async create(report?: TestInfo) {
    return new Hyperswitch(
      await request.newContext({
        baseURL: process.env.HS_BASE_URL ?? "http://localhost:8080",
        timeout: 60_000,
      }),
      report,
    );
  }

  async call(
    method: string,
    path: string,
    key: string,
    data?: Json,
  ): Promise<Json> {
    const invoke = async () => {
      const since = new Date().toISOString();
      const response = await this.fetch(method, path, key, data);
      const requestId = response.headers()["x-request-id"];
      if (this.report && /^\/(payments|refunds)(\/|\?|$)/.test(path)) {
        await test.step("Collect masked UCS audit events", async () => {
          const audit = await collectAudit(
            requestId,
            since,
            this.readAuditLogs,
          );
          if (audit.events.length) {
            for (const event of audit.events) {
              await this.report!.attach(
                `${apiStepName(method, path)} / ${event.flow_type} / ${event.stage}`,
                {
                  body: JSON.stringify(event, null, 2),
                  contentType: "application/json",
                },
              );
            }
          } else {
            this.report!.annotations.push({
              type: `UCS audit: ${apiStepName(method, path)}`,
              description: audit.reason,
            });
          }
        });
      }
      if (!response.ok()) {
        // Never include raw response bodies or keys in test output.
        throw new Error(
          `${method} ${path}: HTTP ${response.status()}, request-id=${requestId ?? "unknown"}`,
        );
      }
      return response.json();
    };
    return this.report
      ? test.step(apiStepName(method, path), invoke)
      : invoke();
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
export async function readUcsGateway(
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
    return {
      processorReference: result.rows[0]?.processor_reference as string,
      gateway: result.rows[0]?.gateway as string,
      processorOutcomeVerified: result.rows[0]
        ?.processor_payment_completed as boolean,
    };
  } finally {
    await client.end();
  }
}

export async function readConnectorRefundReference(
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
    return result.rows[0]?.processor_reference === true;
  } finally {
    await client.end();
  }
}
