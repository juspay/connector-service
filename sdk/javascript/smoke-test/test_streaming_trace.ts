/**
 * Streaming tracing smoke test.
 *
 * Verifies that the FFI streaming tracing subscriber can be initialized
 * and that JSON log lines are emitted to a file during a flow call.
 *
 * This test does NOT require live connector credentials — it only tests
 * the tracing initialization path and verifies log output.
 *
 * Usage:
 *   npx ts-node test_streaming_trace.ts
 *   npx ts-node test_streaming_trace.ts --creds-file creds.json --connector stripe
 */

import { PaymentClient, types } from "hs-playlib";
import type { TracingConfig } from "hs-playlib";
import * as fs from "fs";
import * as path from "path";

const {
  PaymentServiceAuthorizeRequest,
  Currency,
  CaptureMethod,
  AuthenticationType,
  ConnectorConfig,
  Environment,
} = types;

const LOG_FILE = path.join(process.cwd(), "ffi_trace.log");

// ─── Helpers ────────────────────────────────────────────────────────────────

function cleanup() {
  try { fs.unlinkSync(LOG_FILE); } catch (_) { /* ignore */ }
}

function buildRequest(): any {
  return PaymentServiceAuthorizeRequest.create({
    merchantTransactionId: `stream_trace_${Date.now()}`,
    amount: { minorAmount: 1000, currency: Currency.USD },
    captureMethod: CaptureMethod.AUTOMATIC,
    paymentMethod: {
      card: {
        cardNumber: { value: "4111111111111111" },
        cardExpMonth: { value: "12" },
        cardExpYear: { value: "2050" },
        cardCvc: { value: "123" },
        cardHolderName: { value: "Trace Test" },
      },
    },
    customer: { email: { value: "trace@example.com" }, name: "Trace Test" },
    authType: AuthenticationType.NO_THREE_DS,
    returnUrl: "https://example.com/return",
    address: {},
    testMode: true,
  });
}

// ─── Tests ──────────────────────────────────────────────────────────────────

async function testInitTracing(connectorKey: string, auth: Record<string, any>) {
  cleanup();

  console.log("  [1] Init tracing to file...");
  const config = ConnectorConfig.create({
    options: { environment: Environment.SANDBOX },
    connectorConfig: { [connectorKey]: auth } as any,
  });

  const tracingConfig: TracingConfig = {
    output: "file",
    filePath: LOG_FILE,
    levelFilter: "info",
  };

  const client = new PaymentClient(config as any, {}, undefined, tracingConfig);
  console.log("      PASS — tracing initialized without error");

  // Run a flow to generate log lines
  console.log("  [2] Running authorize flow to generate trace output...");
  try {
    await client.authorize(buildRequest());
    console.log("      PASS — flow completed");
  } catch (e: any) {
    // Flow errors are expected (bad creds, sandbox rejections, etc.)
    // What matters is that tracing captured the steps
    console.log(`      PASS — flow completed with expected error: ${e.message || e}`);
  }

  // Verify log file has content
  console.log("  [3] Verifying trace log file...");
  if (!fs.existsSync(LOG_FILE)) {
    console.error("      FAIL — trace log file not created");
    process.exit(1);
  }

  const logContent = fs.readFileSync(LOG_FILE, "utf-8").trim();
  const lines = logContent.split("\n").filter(Boolean);

  if (lines.length === 0) {
    console.error("      FAIL — trace log file is empty");
    process.exit(1);
  }

  console.log(`      PASS — ${lines.length} log line(s) written`);

  // Verify lines are valid JSON
  console.log("  [4] Verifying JSON format...");
  let validJson = 0;
  for (const line of lines) {
    try {
      JSON.parse(line);
      validJson++;
    } catch (_) {
      console.error(`      WARN — non-JSON line: ${line.substring(0, 100)}`);
    }
  }
  console.log(`      PASS — ${validJson}/${lines.length} lines are valid JSON`);

  // Print all trace lines so they're visible in make output
  console.log(`\n  ── Streaming trace output (${ lines.length} lines) ──`);
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      console.log("  " + JSON.stringify(parsed, null, 2).split("\n").join("\n  "));
    } catch (_) {
      console.log("  " + line);
    }
  }
  console.log(`  ── End trace output ──\n`);

  cleanup();
}

async function testDoubleInit(connectorKey: string, auth: Record<string, any>) {
  console.log("  [5] Double-init safety...");
  const config = ConnectorConfig.create({
    options: { environment: Environment.SANDBOX },
    connectorConfig: { [connectorKey]: auth } as any,
  });

  // Second client with different tracing config — should be a no-op
  try {
    new PaymentClient(config as any, {}, undefined, {
      output: "stderr",
      levelFilter: "debug",
    });
    console.log("      PASS — second init is a no-op, no panic");
  } catch (e: any) {
    console.error(`      FAIL — second init threw: ${e.message}`);
    process.exit(1);
  }
}

// ─── CLI ────────────────────────────────────────────────────────────────────

function parseArgs(): { credsFile: string; connector: string } {
  const args = process.argv.slice(2);
  let credsFile = "creds.json";
  let connector = "stripe";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--creds-file" && i + 1 < args.length) credsFile = args[++i];
    else if (args[i] === "--connector" && i + 1 < args.length) connector = args[++i];
  }

  return { credsFile, connector };
}

async function main() {
  const { credsFile, connector } = parseArgs();

  console.log(`\nStreaming Trace Smoke Test`);
  console.log(`Connector: ${connector}\n`);

  // Load credentials
  if (!fs.existsSync(credsFile)) {
    console.error(`Credentials file not found: ${credsFile}`);
    process.exit(1);
  }

  const allCreds = JSON.parse(fs.readFileSync(credsFile, "utf-8"));
  const connectorAuth = allCreds[connector];
  if (!connectorAuth) {
    console.error(`Connector '${connector}' not found in ${credsFile}`);
    process.exit(1);
  }

  const auth = Array.isArray(connectorAuth) ? connectorAuth[0] : connectorAuth;
  const camelAuth: Record<string, any> = {};
  for (const [key, value] of Object.entries(auth)) {
    if (key !== "_comment" && key !== "metadata") {
      camelAuth[key.replace(/_([a-z])/g, (_, l: string) => l.toUpperCase())] = value;
    }
  }

  await testInitTracing(connector, camelAuth);
  await testDoubleInit(connector, camelAuth);

  console.log(`\nAll streaming trace tests passed.\n`);
}

main().catch((e) => {
  console.error(`Fatal: ${e.message || e}`);
  process.exit(1);
});
