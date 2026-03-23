/**
 * gRPC smoke test for hs-playlib SDK.
 *
 * For each supported flow (filtered by data/field_probe/{connector}.json),
 * calls the connector's _build*Request() builder to construct the proto
 * request, then dispatches it directly through the GrpcClient.
 *
 * No grpc_* wrapper functions are needed in the connector JS file.
 *
 * Usage:
 *   node test_smoke_grpc.js --connectors stripe --examples-dir /path/to/examples
 */

import { GrpcClient } from "hs-playlib";
import type { GrpcConfig } from "hs-playlib";
import * as fs from "fs";
import * as path from "path";

// ── ANSI color helpers ──────────────────────────────────────────────────────
const _NO_COLOR = !process.stdout.isTTY || !!process.env["NO_COLOR"];
function _c(code: string, text: string): string { return _NO_COLOR ? text : `\x1b[${code}m${text}\x1b[0m`; }
function _green (t: string): string { return _c("32", t); }
function _red   (t: string): string { return _c("31", t); }
function _grey  (t: string): string { return _c("90", t); }
function _bold  (t: string): string { return _c("1",  t); }

// ── Field-probe support filtering ────────────────────────────────────────────

interface FieldProbe {
  supportedFlows: Set<string>;
  // First supported variant's proto_request per flow — used as payload fallback.
  probeRequests:  Map<string, Record<string, unknown>>;
}

function loadFieldProbe(connector: string, examplesDir: string): FieldProbe | null {
  const probeFile = path.join(examplesDir, "..", "data", "field_probe", `${connector}.json`);
  if (!fs.existsSync(probeFile)) return null;
  const probe = JSON.parse(fs.readFileSync(probeFile, "utf-8")) as {
    flows?: Record<string, Record<string, { status: string; proto_request?: Record<string, unknown> }>>;
  };
  if (!probe.flows) return null;
  const supportedFlows = new Set<string>();
  const probeRequests  = new Map<string, Record<string, unknown>>();
  for (const [flowName, variants] of Object.entries(probe.flows)) {
    const supportedVariant = Object.values(variants).find((v) => v.status === "supported");
    if (supportedVariant) {
      supportedFlows.add(flowName);
      if (supportedVariant.proto_request) {
        probeRequests.set(flowName, supportedVariant.proto_request);
      }
    }
  }
  return { supportedFlows, probeRequests };
}

// ── Flow gRPC dispatch metadata ──────────────────────────────────────────────
// Maps flow key → GrpcClient field/method + connector builder function name + arg type.
//
// arg: "AUTOMATIC"/"MANUAL" = string literal forwarded to builder (capture_method);
//      "txnId"              = connector txn_id (from shared authorize pre-run);
//      "none"               = builder takes no arguments.

interface FlowMeta {
  field:   string;   // GrpcClient field  (e.g. "payment", "customer")
  method:  string;   // camelCase method  (e.g. "authorize", "create")
  builder: string;   // _build*Request fn exported by the connector's JS module
  arg:     "AUTOMATIC" | "MANUAL" | "txnId" | "none";
}

// Canonical ordering matches Rust build.rs.
const FLOW_META: [string, FlowMeta][] = [
  ["authorize",                { field: "payment",          method: "authorize",             builder: "_buildAuthorizeRequest",            arg: "AUTOMATIC" }],
  ["capture",                  { field: "payment",          method: "capture",               builder: "_buildCaptureRequest",              arg: "txnId"     }],
  ["void",                     { field: "payment",          method: "void",                  builder: "_buildVoidRequest",                 arg: "txnId"     }],
  ["get",                      { field: "payment",          method: "get",                   builder: "_buildGetRequest",                  arg: "txnId"     }],
  ["refund",                   { field: "payment",          method: "refund",                builder: "_buildRefundRequest",               arg: "txnId"     }],
  ["reverse",                  { field: "payment",          method: "reverse",               builder: "_buildReverseRequest",              arg: "txnId"     }],
  ["create_customer",          { field: "customer",         method: "create",                builder: "_buildCreateCustomerRequest",       arg: "none"      }],
  ["tokenize",                 { field: "paymentMethod",    method: "tokenize",              builder: "_buildTokenizeRequest",             arg: "none"      }],
  ["setup_recurring",          { field: "payment",          method: "setupRecurring",        builder: "_buildSetupRecurringRequest",       arg: "none"      }],
  ["recurring_charge",         { field: "recurringPayment", method: "charge",                builder: "_buildRecurringChargeRequest",      arg: "none"      }],
  ["pre_authenticate",         { field: "payment",          method: "preAuthenticate",       builder: "_buildPreAuthenticateRequest",      arg: "none"      }],
  ["authenticate",             { field: "payment",          method: "authenticate",          builder: "_buildAuthenticateRequest",         arg: "none"      }],
  ["post_authenticate",        { field: "payment",          method: "postAuthenticate",      builder: "_buildPostAuthenticateRequest",     arg: "none"      }],
  ["handle_event",             { field: "payment",          method: "handleEvent",           builder: "_buildHandleEventRequest",          arg: "none"      }],
  ["create_access_token",      { field: "payment",          method: "createAccessToken",     builder: "_buildCreateAccessTokenRequest",    arg: "none"      }],
  ["create_session_token",     { field: "payment",          method: "createSessionToken",    builder: "_buildCreateSessionTokenRequest",   arg: "none"      }],
  ["create_sdk_session_token", { field: "payment",          method: "createSdkSessionToken", builder: "_buildCreateSdkSessionTokenRequest", arg: "none"    }],
];
const FLOW_META_MAP = new Map<string, FlowMeta>(FLOW_META);

// Flows that need a MANUAL authorize inline before calling (capture method mismatch).
const SELF_AUTH_FLOWS = new Set(["capture", "void"]);
// Flows that receive the connector txn_id from the shared AUTOMATIC pre-run authorize.
const TXN_ID_FLOWS    = new Set(["get", "refund", "reverse"]);

// ── CLI args ─────────────────────────────────────────────────────────────────

function parseArgs(): { connectors: string[]; examplesDir: string } {
  const args = process.argv.slice(2);
  let connectors: string[] = ["stripe"];
  let examplesDir = path.join(__dirname, "../../../examples");
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--connectors" && args[i + 1]) {
      connectors = args[++i].split(",").map((s) => s.trim());
    } else if (args[i] === "--examples-dir" && args[i + 1]) {
      examplesDir = args[++i];
    }
  }
  return { connectors, examplesDir };
}

// ── Credentials ──────────────────────────────────────────────────────────────

type CredEntry = Record<string, unknown>;

function loadCreds(credsFile: string): Record<string, CredEntry | CredEntry[]> {
  if (!fs.existsSync(credsFile)) return {};
  const raw: CredEntry = JSON.parse(fs.readFileSync(credsFile, "utf-8"));
  if (typeof raw["connector"] === "string" && typeof raw["endpoint"] === "string") {
    return { [raw["connector"] as string]: raw };
  }
  return raw as unknown as Record<string, CredEntry | CredEntry[]>;
}

function credStr(cred: CredEntry, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const val = cred[key];
    if (typeof val === "string" && val) return val;
    if (val !== null && typeof val === "object") {
      const inner = (val as Record<string, unknown>)["value"];
      if (typeof inner === "string" && inner) return inner;
    }
  }
  return undefined;
}

function buildGrpcConfig(connector: string, cred: CredEntry): GrpcConfig {
  return {
    endpoint:    credStr(cred, "endpoint")                    ?? "http://localhost:8000",
    connector,
    auth_type:   credStr(cred, "auth_type",   "authType")    ?? "header-key",
    api_key:     credStr(cred, "api_key",     "apiKey")      ?? "placeholder",
    api_secret:  credStr(cred, "api_secret",  "apiSecret"),
    key1:        credStr(cred, "key1"),
    merchant_id: credStr(cred, "merchant_id", "merchantId"),
    tenant_id:   credStr(cred, "tenant_id",   "tenantId"),
  };
}

// ── Request building ──────────────────────────────────────────────────────────

/**
 * Build a proto request using the connector's _build*Request() exported function.
 * Falls back to the field_probe proto_request for the flow if the builder is not exported,
 * or {} as a last resort.
 * `arg` is forwarded as the builder's first argument (capture_method or txn_id).
 */
function buildRequest(
  mod: Record<string, unknown>,
  flow: string,
  arg?: string,
  probeRequests?: Map<string, Record<string, unknown>>,
): unknown {
  const meta = FLOW_META_MAP.get(flow);
  if (!meta) return probeRequests?.get(flow) ?? {};
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = typeof mod[meta.builder] === "function" ? (mod[meta.builder] as (...a: any[]) => unknown) : null;
  if (!fn) return probeRequests?.get(flow) ?? {};
  return meta.arg === "none" ? fn() : fn(arg ?? "");
}

// ── txn_id extraction ─────────────────────────────────────────────────────────

function extractTxnId(connectorTransactionId: string | undefined): string {
  return connectorTransactionId ?? "probe_connector_txn_001";
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function runConnector(
  connectorName: string,
  examplesDir:   string,
  cred:          CredEntry,
): Promise<boolean> {
  const jsFile = path.join(examplesDir, connectorName, "javascript", `${connectorName}.js`);
  if (!fs.existsSync(jsFile)) {
    console.log(_grey(`  [${connectorName}] No JavaScript file found at ${jsFile}, skipping.`));
    return true;
  }
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod: Record<string, unknown> = require(jsFile);

  const config = buildGrpcConfig(connectorName, cred);
  const client = new GrpcClient(config);

  // Filter to supported flows (field_probe); null means no filter.
  const fieldProbe = loadFieldProbe(connectorName, examplesDir);
  const probeRequests = fieldProbe?.probeRequests;
  if (fieldProbe !== null) {
    console.log(_grey(`  [${connectorName}] field_probe: ${fieldProbe.supportedFlows.size} supported flows`));
  }

  const presentFlows = FLOW_META
    .map(([flow]) => flow)
    .filter((flow) => fieldProbe === null || fieldProbe.supportedFlows.has(flow));

  if (presentFlows.length === 0) {
    console.log(_grey(`  [${connectorName}] No flows to run, skipping.`));
    return true;
  }

  const txnId = `probe_js_grpc_${Date.now()}`;
  let authorizeTxnId = txnId;

  const hasAuthorize  = presentFlows.includes("authorize");
  const hasDependents = presentFlows.some((f) => TXN_ID_FLOWS.has(f));

  // Pre-run AUTOMATIC authorize to get a real connector txn_id for get/refund/reverse.
  let preRunFailed = false;
  if (hasAuthorize && hasDependents) {
    try {
      const req = buildRequest(mod, "authorize", "AUTOMATIC", probeRequests);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const res = await (client as any).payment.authorize(req) as { connectorTransactionId?: string; statusCode: number };
      authorizeTxnId = extractTxnId(res.connectorTransactionId);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(_red(`  ✗ ${connectorName}::authorize (pre-run)`), _grey(`→ ${msg}`));
      preRunFailed = true;
    }
  }

  let allPassed = true;

  for (const flow of presentFlows) {
    const meta = FLOW_META_MAP.get(flow)!;

    // Skip authorize if already handled in the pre-run above.
    if (flow === "authorize" && hasAuthorize && hasDependents) {
      if (!preRunFailed) {
        console.log(_green(`  ✓ ${connectorName}::authorize (pre-run for txn_id)`));
      }
      continue;
    }

    try {
      let result: string;

      if (SELF_AUTH_FLOWS.has(flow)) {
        // capture / void: do a MANUAL authorize inline (AUTOMATIC txn_id can't be captured).
        const authReq = buildRequest(mod, "authorize", "MANUAL", probeRequests);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const auth = await (client as any).payment.authorize(authReq) as { connectorTransactionId?: string; statusCode: number; error?: unknown };
        if (auth.statusCode >= 400) {
          throw new Error(`inline authorize failed (status ${auth.statusCode})`);
        }
        const selfTxnId = auth.connectorTransactionId ?? txnId;
        const req = buildRequest(mod, flow, selfTxnId, probeRequests);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const res = await (client as any)[meta.field][meta.method](req) as { connectorTransactionId?: string; statusCode: number };
        result = `txn_id: ${res.connectorTransactionId ?? "-"}, status_code: ${res.statusCode}`;
      } else {
        const arg = TXN_ID_FLOWS.has(flow) ? authorizeTxnId : txnId;
        const req = buildRequest(mod, flow, arg, probeRequests);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const res = await (client as any)[meta.field][meta.method](req) as Record<string, unknown>;
        result = `status_code: ${res["statusCode"] ?? "?"}`;
      }

      console.log(_green(`  ✓ ${connectorName}::${flow}`), _grey(`→ ${result}`));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(_red(`  ✗ ${connectorName}::${flow}`), _grey(`→ ${msg}`));
      allPassed = false;
    }
  }

  return allPassed;
}

async function main(): Promise<void> {
  const { connectors, examplesDir } = parseArgs();

  const credsFile = path.join(process.cwd(), "creds.json");
  const allCreds  = loadCreds(credsFile);

  console.log(_bold("hyperswitch gRPC smoke test"));
  console.log(_grey(`connectors: ${connectors.join(", ")}`));
  console.log();

  let anyFailed = false;

  for (const connector of connectors) {
    console.log(_bold(`── ${connector} ──`));

    const raw = allCreds[connector];
    const creds: CredEntry[] = Array.isArray(raw) ? raw : raw ? [raw] : [{}];

    for (const cred of creds) {
      const passed = await runConnector(connector, examplesDir, cred);
      if (!passed) anyFailed = true;
    }
    console.log();
  }

  if (anyFailed) {
    console.error(_red("Some gRPC tests FAILED."));
    process.exit(1);
  } else {
    console.log(_green("All gRPC tests passed."));
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
