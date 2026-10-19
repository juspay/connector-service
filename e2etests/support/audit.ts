import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
type AuditEvent = Record<string, unknown>;
export type AuditSnapshot = {
  status: "collected" | "unavailable";
  reason?: string;
  events: AuditEvent[];
};

// Only consume the structured field emitted AFTER UCS masking/transformation.
// Never parse human-readable messages or attach surrounding container logs.
export function matchingEvents(lines: string, requestId: string): AuditEvent[] {
  const events: AuditEvent[] = [];
  for (const line of lines.split("\n")) {
    try {
      const record = JSON.parse(line);
      if (typeof record?.ucs_event !== "string") continue;
      const event = JSON.parse(record.ucs_event);
      if (
        event?.request_id === requestId &&
        ["GrpcRequest", "ConnectorCall"].includes(event.stage) &&
        typeof event.timestamp === "number" &&
        Number.isFinite(event.timestamp)
      )
        events.push(event);
    } catch {
      // Other log lines, including old message-only events, are not evidence.
    }
  }
  // Stable sort preserves source order when timestamps tie. Keep repeated calls.
  return events.sort(
    (a, b) => (a.timestamp as number) - (b.timestamp as number),
  );
}

type ReadLogs = (since: string) => Promise<string>;
export function createDockerLogReader(): ReadLogs {
  let selected: Promise<string> | undefined;
  const docker = async (args: string[]) => {
    const { stdout, stderr } = await execFileAsync("docker", args, {
      timeout: 5_000,
      maxBuffer: 16 * 1024 * 1024,
      encoding: "utf8",
    });
    return `${stdout}\n${stderr}`;
  };
  return async (since) => {
    selected ??= (async () => {
      const explicit = process.env.UCS_LOG_CONTAINER;
      if (explicit) {
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(explicit)) throw new Error();
        return explicit;
      }
      const containers = (
        await docker([
          "ps",
          "--filter",
          "label=com.docker.compose.project=ucs-e2e",
          "--filter",
          "label=com.docker.compose.service=ucs",
          "--format",
          "{{.ID}}",
        ])
      )
        .trim()
        .split(/\s+/)
        .filter(Boolean);
      if (containers.length !== 1) throw new Error();
      return containers[0];
    })();
    return docker(["logs", "--since", since, "--", await selected]);
  };
}

export async function collectAudit(
  requestId: string | undefined,
  since: string,
  readLogs: ReadLogs,
): Promise<AuditSnapshot> {
  if (!requestId)
    return {
      status: "unavailable",
      reason: "HS response has no request ID",
      events: [],
    };
  try {
    // UCS emits at RPC completion; allow one short retry for buffered logging.
    for (let attempt = 0; attempt < 2; attempt++) {
      const events = matchingEvents(await readLogs(since), requestId);
      if (events.length) return { status: "collected", events };
      if (attempt === 0)
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return {
      status: "unavailable",
      reason: "No matching structured UCS events in this log snapshot",
      events: [],
    };
  } catch {
    // Docker errors may quote container output. Never forward their contents.
    return {
      status: "unavailable",
      reason: "UCS container logs could not be read within collection limits",
      events: [],
    };
  }
}
