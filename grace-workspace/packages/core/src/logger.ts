import { WebSocketServer, WebSocket } from "ws";
import { nowIso } from "./utils.js";
import type { CheckpointId, CheckpointStatus } from "./types.js";

type Level = "info" | "warn" | "error" | "success" | "debug";

const COLORS: Record<Level, string> = {
  info: "\x1b[36m",
  warn: "\x1b[33m",
  error: "\x1b[31m",
  success: "\x1b[32m",
  debug: "\x1b[90m",
};
const RESET = "\x1b[0m";

export interface EventEnvelope {
  runId: string;
  checkpointId?: CheckpointId;
  timestamp: string;
  type: string;
  payload?: unknown;
}

type InboundHandler = (msg: { type: string; payload?: unknown }) => void;

export class PipelineEventBus {
  private wss?: WebSocketServer;
  private clients = new Set<WebSocket>();
  private runId: string;
  private inboundHandlers = new Set<InboundHandler>();
  private lastSnapshot: Array<EventEnvelope> = [];

  constructor(runId: string, wsPort?: number) {
    this.runId = runId;
    if (wsPort) {
      try {
        this.wss = new WebSocketServer({ port: wsPort });
        this.wss.on("connection", (ws) => {
          this.clients.add(ws);
          // Replay recent events so a late-connecting dashboard sees context
          for (const e of this.lastSnapshot) {
            try {
              ws.send(JSON.stringify(e));
            } catch {
              /* ignore */
            }
          }
          ws.on("message", (raw) => {
            try {
              const parsed = JSON.parse(raw.toString()) as {
                type: string;
                payload?: unknown;
              };
              for (const h of this.inboundHandlers) h(parsed);
            } catch {
              /* ignore malformed */
            }
          });
          ws.on("close", () => this.clients.delete(ws));
        });
      } catch (e) {
        console.error(`[events] Failed to start WS server on ${wsPort}:`, e);
      }
    }
  }

  onInbound(handler: InboundHandler): () => void {
    this.inboundHandlers.add(handler);
    return () => this.inboundHandlers.delete(handler);
  }

  waitFor<T = unknown>(type: string, timeoutMs?: number): Promise<T> {
    return new Promise((resolve, reject) => {
      const off = this.onInbound((msg) => {
        if (msg.type === type) {
          off();
          if (timer) clearTimeout(timer);
          resolve(msg.payload as T);
        }
      });
      let timer: NodeJS.Timeout | undefined;
      if (timeoutMs && timeoutMs > 0) {
        timer = setTimeout(() => {
          off();
          reject(new Error(`Timed out waiting for inbound ${type}`));
        }, timeoutMs);
      }
    });
  }

  emit(type: string, checkpointId?: CheckpointId, payload?: unknown) {
    const envelope: EventEnvelope = {
      runId: this.runId,
      checkpointId,
      timestamp: nowIso(),
      type,
      payload,
    };
    this.lastSnapshot.push(envelope);
    if (this.lastSnapshot.length > 500) this.lastSnapshot.shift();
    const serialized = JSON.stringify(envelope);
    for (const c of this.clients) {
      if (c.readyState === WebSocket.OPEN) c.send(serialized);
    }
  }

  log(
    checkpointId: CheckpointId | "pipeline",
    msg: string,
    level: Level = "info"
  ) {
    const ts = nowIso();
    const line = `${COLORS[level]}${ts} [${checkpointId}] ${level.toUpperCase()}${RESET} ${msg}`;
    // eslint-disable-next-line no-console
    console.log(line);
    this.emit("log", checkpointId === "pipeline" ? undefined : checkpointId, {
      msg,
      level,
    });
  }

  emitCheckpoint(
    type: "checkpoint:start" | "checkpoint:pass" | "checkpoint:fail" | "checkpoint:retry",
    checkpointId: CheckpointId,
    extra?: Record<string, unknown>
  ) {
    this.emit(type, checkpointId, extra);
  }

  emitStatus(checkpointId: CheckpointId, status: CheckpointStatus) {
    this.emit("checkpoint:status", checkpointId, { status });
  }

  emitHumanWaiting(checkpointId: CheckpointId, spec: unknown) {
    this.emit("human:waiting", checkpointId, { spec });
  }

  emitHumanResolved(checkpointId: CheckpointId, decision: string) {
    this.emit("human:resolved", checkpointId, { decision });
  }

  close() {
    for (const c of this.clients) c.close();
    this.wss?.close();
  }
}
