import path from "node:path";
import { promises as fs } from "node:fs";
import net from "node:net";
import { spawn } from "node:child_process";
import type { Checkpoint, RepairBrief } from "../types.js";
import { runAI } from "../tools/runner-factory.js";

/**
 * gRPC Test Checkpoint - Phase 6-7 gRPC testing from 2.3_codegen.md
 *
 * Runs grpcurl tests to validate the connector implementation.
 * Replaces: Design Match, Cypress E2E Test, Playwright Tests
 * Does NOT modify source files — when the test fails, the engine rolls back
 * to `implementation` (see retryFrom) and a structured `repairBrief` artifact
 * carries the diagnosis (server log tail, root-cause file:line, error kind)
 * so the next pass through `implementation` can fix the underlying bug.
 */
export const grpcTestCheckpoint: Checkpoint = {
  id: "grpc_test",
  name: "gRPC Test",
  description: "Test connector via gRPC calls using grpcurl (replaces Design Match/Cypress/Playwright)",
  // On failure, roll back to `implementation` — only the writer can fix the
  // underlying code bug. Re-running grpc_test against unchanged code never
  // changes the outcome. The `repairBrief` artifact below tells the writer
  // what to fix.
  retryFrom: "implementation",
  timeout: 10 * 60 * 1000, // 10 min for testing

  async run(ctx) {
    const task = ctx.artifacts.task;
    const connector = task?.targetConnectors?.[0];
    const flow = task?.paymentMethod || "Unknown";
    const projectRoot = task?.projectRoot;

    if (!projectRoot) {
      return { passed: false, errors: ["Missing project root"] };
    }

    ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "info");
    ctx.log("[grpc_test] ║  gRPC Test (2.3_codegen.md Phase 6-7)                  ║", "info");
    ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "info");
    ctx.log(`[grpc_test] Connector: ${connector}`, "info");
    ctx.log(`[grpc_test] Flow: ${flow}`, "info");

    // ── Pre-flight: make sure grpc-server is reachable on localhost:8000 ──
    const startTs = Date.now();
    let serverLogPath = ctx.artifacts.grpcServerLogPath;
    try {
      const reachable = await tcpProbe("127.0.0.1", 8000, 1000);
      if (!reachable) {
        ctx.log("[grpc_test] grpc-server not reachable on :8000 — starting it", "warn");
        serverLogPath = await spawnGrpcServer(projectRoot);
        ctx.artifacts.grpcServerLogPath = serverLogPath;
        const ready = await waitForGrpcReadiness("127.0.0.1", 8000, 60_000);
        if (!ready) {
          return {
            passed: false,
            errors: ["grpc-server failed to become ready within 60s"],
            artifacts: {
              repairBrief: {
                source: "grpc_test",
                flow,
                errorKind: "infra",
              } satisfies RepairBrief,
            },
          };
        }
        ctx.log("[grpc_test] grpc-server is up", "success");
      } else {
        ctx.log("[grpc_test] grpc-server already running on :8000", "info");
      }
    } catch (err) {
      ctx.log(`[grpc_test] Pre-flight error: ${err instanceof Error ? err.message : String(err)}`, "warn");
    }

    // Read workflow file
    let workflowContent = "";
    try {
      const workflowPath = path.join(projectRoot, "grace/workflow/2.3_codegen.md");
      workflowContent = await fs.readFile(workflowPath, 'utf-8');
      ctx.log("[grpc_test] Loaded workflow file", "info");
    } catch (err) {
      ctx.log(`[grpc_test] Warning: Could not read workflow: ${err}`, "warn");
    }

    // Parse field_probe data so we hand the LLM materialised values, not just a path
    let fieldProbe: unknown = null;
    let fieldProbePath: string | null = null;
    try {
      const probePath = path.join(projectRoot, "data", "field_probe", `${connector?.toLowerCase() || "unknown"}.json`);
      const raw = await fs.readFile(probePath, 'utf-8');
      fieldProbe = JSON.parse(raw);
      fieldProbePath = probePath;
      ctx.log(`[grpc_test] Field probe loaded: ${probePath}`, "info");
    } catch {
      ctx.log("[grpc_test] No field probe data available", "warn");
    }

    // Build restricted system prompt
    const systemPrompt = `You are the gRPC Test Agent.

## CRITICAL RESTRICTION - TEST-ONLY MODE
You are in TEST-ONLY MODE.

**EXECUTE ONLY:**
- Phase 6-7: gRPC testing (grpcurl)

**DO NOT EXECUTE:**
- Phase 4 (Read & Analyze) - already done
- Phase 5 (Implement) - code already written
- cargo build - already done by Compiler Check
- Do NOT modify source files
- Do NOT rebuild

You MUST:
1. Read the workflow below
2. Find the gRPC testing steps in Phase 6-7
3. The grpc-server is already running on localhost:8000 (started by the checkpoint host).
4. Build the gRPC request body. Prefer values from FIELD_PROBE (already
   parsed and supplied below) over generating your own. Use L3_STATUS_MAPPING
   to know which response codes/fields indicate success vs error.
5. Run grpcurl tests against localhost:8000
6. Report test results including FULL grpcurl command and FULL response.
7. If the test fails, include any server-log tail you can capture so the next
   step has root-cause information.

## Output Format

Return ONLY valid JSON:
{
  "status": "SUCCESS" | "FAILED",
  "grpcurl_result": "PASS" | "FAIL",
  "grpcurl_command": "the full grpcurl command used",
  "grpcurl_output": "the full output including command and response",
  "response_summary": "brief summary of the response received",
  "server_log_tail": "optional: recent grpc-server stderr/stdout lines you captured"
}

## Workflow File (execute ONLY Phase 6-7 gRPC testing)
${workflowContent}
`;

    const payload = {
      CONNECTOR: connector,
      FLOW: flow,
      FIELD_PROBE: fieldProbe,
      FIELD_PROBE_PATH: fieldProbePath ?? "",
      L3_STATUS_MAPPING: (ctx.artifacts.l3 as { statusMapping?: unknown } | undefined)?.statusMapping ?? null,
      SERVER_HOST: "localhost:8000",
      CREDS_PATH: path.join(projectRoot, "creds.json"),
    };

    ctx.log("[grpc_test] Starting gRPC tests...", "warn");

    type GrpcTestResult = {
      status?: string;
      grpcurl_result?: string;
      grpcurl_command?: string;
      grpcurl_output?: string;
      response_summary?: string;
      server_log_tail?: string;
      output?: string;
      reason?: string;
    };

    try {
      const result = await runAI<GrpcTestResult>({
        skillBody: systemPrompt,
        userPayload: payload,
        cwd: projectRoot,
        label: "grpc:test",
        timeoutMs: 8 * 60 * 1000, // 8 min for testing
      });

      const grpcCommand = result.grpcurl_command || "";
      const grpcOutput = result.grpcurl_output || result.output || "";
      const responseSummary = result.response_summary || "";

      // ── Structural success check (catches silent-empty-body false positives) ──
      const grpcurlOk = result.status === "SUCCESS" || result.grpcurl_result === "PASS";
      const requestBodyCheck = checkRawConnectorRequestBody(grpcOutput);
      let testPassed = grpcurlOk;
      let structuralFailReason: string | null = null;
      if (grpcurlOk && requestBodyCheck === "empty") {
        testPassed = false;
        structuralFailReason =
          "rawConnectorRequest.body is empty {} — the request transformer produced no body. " +
          "The remote endpoint may have accepted it incidentally; treating as FAIL because the " +
          "implementation under review was not actually exercised.";
        ctx.log(`[grpc_test] ${structuralFailReason}`, "error");
      }

      // Build output for UI display
      const uiOutput = `gRPC Test Results
═══════════════════════════════════════════════════════════════

COMMAND USED:
${grpcCommand || "Not captured"}

RESPONSE RECEIVED:
${responseSummary || grpcOutput.slice(0, 2000)}

FULL OUTPUT:
${grpcOutput.slice(0, 3000)}
${structuralFailReason ? `\nSTRUCTURAL CHECK: ${structuralFailReason}\n` : ""}`;

      if (testPassed) {
        ctx.log("[grpc_test] ✓ gRPC tests passed", "success");
        ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "success");
        ctx.log("[grpc_test] ║  ✓ gRPC Test Passed                                      ║", "success");
        ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "success");

        return {
          passed: true,
          output: uiOutput,
          artifacts: {
            grpcTest: result,
            grpcurlOutput: grpcOutput,
            grpcurlCommand: grpcCommand,
            grpcResponse: responseSummary,
            // Clear any stale repairBrief on success — we're past the failure.
            repairBrief: undefined,
          },
        };
      } else {
        ctx.log("[grpc_test] ⚠ gRPC tests failed", "warn");
        ctx.log("[grpc_test] ╔═══════════════════════════════════════════════════════════╗", "warn");
        ctx.log("[grpc_test] ║  ⚠ gRPC Test Failed - Recording details                ║", "warn");
        ctx.log("[grpc_test] ╚═══════════════════════════════════════════════════════════╝", "warn");

        const errorMsg = result.reason || structuralFailReason || "gRPC test failed";

        // Capture server log tail (LLM-supplied, with file fallback) for the repair brief
        const fileLogTail = await tailServerLog(serverLogPath, startTs);
        const serverLogTail = result.server_log_tail || fileLogTail;

        const repairBrief: RepairBrief = {
          source: "grpc_test",
          flow,
          grpcurlCommand: grpcCommand,
          grpcurlOutput: grpcOutput,
          responseSummary,
          serverLogTail,
          rootCauseFile: extractRootCauseFile(grpcOutput, serverLogTail),
          rootCauseLine: extractRootCauseLine(grpcOutput, serverLogTail),
          errorKind: classifyError(grpcOutput, serverLogTail, structuralFailReason),
        };

        // Store errors for implementation retry
        ctx.artifacts.grpcTestErrors = [errorMsg, grpcOutput].filter(Boolean) as string[];
        ctx.artifacts.grpcurlOutput = grpcOutput;

        return {
          passed: false,
          output: uiOutput,
          errors: [errorMsg],
          artifacts: {
            grpcTest: result,
            grpcurlOutput: grpcOutput,
            grpcurlCommand: grpcCommand,
            grpcResponse: responseSummary,
            repairBrief,
          },
        };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[grpc_test] gRPC test failed: ${msg}`, "error");
      const serverLogTail = await tailServerLog(serverLogPath, startTs);
      const repairBrief: RepairBrief = {
        source: "grpc_test",
        flow,
        errorKind: msg.includes("timed out") ? "infra" : "unknown",
        serverLogTail,
        rootCauseFile: extractRootCauseFile("", serverLogTail),
        rootCauseLine: extractRootCauseLine("", serverLogTail),
      };
      return {
        passed: false,
        output: `gRPC Test Error: ${msg}`,
        errors: [`gRPC test failed: ${msg}`],
        artifacts: { repairBrief },
      };
    }
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function tcpProbe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}

async function waitForGrpcReadiness(host: string, port: number, totalMs: number): Promise<boolean> {
  const deadline = Date.now() + totalMs;
  while (Date.now() < deadline) {
    if (await tcpProbe(host, port, 1000)) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

async function spawnGrpcServer(projectRoot: string): Promise<string> {
  const logDir = path.join(projectRoot, "data", "logs");
  await fs.mkdir(logDir, { recursive: true });
  const logPath = path.join(logDir, `grpc-server-${Date.now()}.log`);
  const fh = await fs.open(logPath, "w");
  const child = spawn("cargo", ["run", "--bin", "grpc-server"], {
    cwd: projectRoot,
    detached: true,
    stdio: ["ignore", fh.fd, fh.fd],
    env: process.env,
  });
  child.unref();
  // Close the fd in the parent — the child has its own copy.
  await fh.close();
  return logPath;
}

async function tailServerLog(logPath: string | undefined, sinceTs: number): Promise<string> {
  if (!logPath) return "";
  try {
    const stat = await fs.stat(logPath);
    if (stat.mtimeMs < sinceTs - 5_000) return ""; // stale log; not from this run
    const content = await fs.readFile(logPath, "utf-8");
    // Last ~6 KB is enough to surface the most recent error stack
    return content.slice(-6_000);
  } catch {
    return "";
  }
}

function checkRawConnectorRequestBody(grpcOutput: string): "empty" | "non_empty" | "absent" {
  // The proto wraps the raw request as a JSON-encoded string, so what shows
  // up in grpcurl output is escaped JSON inside a "value" field. Match either
  // the wrapped form or a plain "body": {...} substring.
  const wrapped = grpcOutput.match(/"rawConnectorRequest"\s*:\s*\{[^}]*"value"\s*:\s*"((?:[^"\\]|\\.)+)"/);
  if (wrapped) {
    try {
      const inner = JSON.parse(`"${wrapped[1]}"`);
      const decoded: unknown = JSON.parse(inner);
      if (
        decoded && typeof decoded === "object" &&
        "body" in (decoded as Record<string, unknown>)
      ) {
        const body = (decoded as { body: unknown }).body;
        if (body && typeof body === "object" && Object.keys(body as Record<string, unknown>).length > 0) {
          return "non_empty";
        }
        return "empty";
      }
    } catch {
      /* fall through */
    }
  }
  const plain = grpcOutput.match(/"body"\s*:\s*\{([^}]*)\}/);
  if (plain) {
    return plain[1].trim().length === 0 ? "empty" : "non_empty";
  }
  return "absent";
}

function extractRootCauseFile(grpcOutput: string, serverLogTail: string): string | undefined {
  const haystack = `${serverLogTail}\n${grpcOutput}`;
  // Prefer "at <crate>/.../<file>.rs:<line>" patterns (tracing default)
  const at = haystack.match(/at\s+([^\s:]+\.rs):\d+/);
  if (at) return at[1];
  // Fall back to "<file>.rs:<line>" anywhere
  const any = haystack.match(/([\w/.-]+\.rs):\d+/);
  return any?.[1];
}

function extractRootCauseLine(grpcOutput: string, serverLogTail: string): number | undefined {
  const haystack = `${serverLogTail}\n${grpcOutput}`;
  const at = haystack.match(/at\s+[^\s:]+\.rs:(\d+)/);
  if (at) return Number(at[1]);
  const any = haystack.match(/[\w/.-]+\.rs:(\d+)/);
  return any ? Number(any[1]) : undefined;
}

function classifyError(
  grpcOutput: string,
  serverLogTail: string,
  structuralFailReason: string | null,
): RepairBrief["errorKind"] {
  if (structuralFailReason) return "transform_error";
  const haystack = `${serverLogTail}\n${grpcOutput}`;
  if (/MissingRequiredField|Missing required field/i.test(haystack)) return "missing_field";
  if (/Transformation error|TryFrom|ConnectorRequest/i.test(haystack)) return "transform_error";
  if (/InvalidArgument|status_code: \"Client specified an invalid argument\"/i.test(haystack)) return "transform_error";
  if (/connection refused|Connection refused|tcp connect error/i.test(haystack)) return "infra";
  if (/HTTP\s+(4\d\d|5\d\d)/i.test(haystack)) return "http_error";
  if (/timed out|timeout/i.test(haystack)) return "infra";
  return "unknown";
}
