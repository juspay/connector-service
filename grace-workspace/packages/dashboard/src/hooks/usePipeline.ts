import { useEffect, useRef, useState } from "react";

export type CheckpointStatus =
  | "idle"
  | "running"
  | "passed"
  | "failed"
  | "skipped";

export interface CheckpointState {
  id: string;
  status: CheckpointStatus;
  retries: number;
  waiting?: { spec: unknown } | null;
  errors?: string[];
  lastEventTs?: string;
}

export interface LogLine {
  ts: string;
  checkpointId?: string;
  msg: string;
  level: string;
}

export interface RetryStep {
  checkpointId: string;
  rollbackTo: string;
  attempt: number;
  ts: string;
}

export type JourneyEventKind = "started" | "passed" | "failed" | "rollback";

export interface JourneyEvent {
  kind: JourneyEventKind;
  checkpointId: string;
  /** For rollback events: which checkpoint we rolled back to. */
  rollbackTo?: string;
  attempt: number;
  ts: string;
}

// Grace 2.3_codegen.md workflow: task → preflight → L2_planning → L3_analysis → implementation
// Removed: product_alignment, feature_research, design_gate, requirements, l4_gen, l4_review
export const PIPELINE: Array<{ id: string; name: string; type: "auto" | "human" }> = [
  { id: "task", name: "Task definition", type: "auto" },
  { id: "preflight", name: "Preflight setup", type: "auto" },
  { id: "l2_planning", name: "L2 Planning", type: "auto" },
  { id: "l2_review", name: "Human review: L2 plan", type: "human" },
  { id: "l3_analysis", name: "L3 Analysis", type: "auto" },
  { id: "l3_review", name: "Human review: L3 analysis", type: "human" },
  { id: "implementation", name: "Implementation", type: "auto" },
  { id: "compiler", name: "Compiler check", type: "auto" },
  { id: "design_match", name: "Design match", type: "auto" },
  { id: "cypress", name: "Cypress E2E tests", type: "auto" },
  { id: "playwright", name: "Playwright tests", type: "auto" },
  { id: "pr_review", name: "PR review", type: "human" },
  { id: "regression", name: "Regression testing", type: "auto" },
];

export type PipelineStatus = "idle" | "running" | "complete" | "aborted";

export function usePipeline(wsUrl: string) {
  const [runId, setRunId] = useState<string | undefined>();
  const [states, setStates] = useState<Record<string, CheckpointState>>(() => {
    const o: Record<string, CheckpointState> = {};
    for (const cp of PIPELINE) o[cp.id] = { id: cp.id, status: "idle", retries: 0 };
    return o;
  });
  const [logsByCp, setLogsByCp] = useState<Record<string, LogLine[]>>({});
  const [allLogs, setAllLogs] = useState<LogLine[]>([]);
  const [retries, setRetries] = useState<RetryStep[]>([]);
  const [journey, setJourney] = useState<JourneyEvent[]>([]);
  const [artifacts, setArtifacts] = useState<Record<string, unknown>>({});
  const [wsStatus, setWsStatus] = useState<"connecting" | "open" | "closed">(
    "connecting"
  );
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus>("idle");
  const [abortReason, setAbortReason] = useState<string | null>(null);
  const [savedRuns, setSavedRuns] = useState<any[]>([]);
  const [lastRejection, setLastRejection] = useState<{
    checkpointId: string;
    reason: string;
    ts: string;
  } | null>(null);
  const [autoMode, setAutoModeState] = useState<{
    enabled: boolean;
    agentName?: string;
  }>({ enabled: false });
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let cancelled = false;
    let retryTimer: number | undefined;

    const connect = () => {
      if (cancelled) return;
      setWsStatus("connecting");
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => setWsStatus("open");
      ws.onclose = () => {
        setWsStatus("closed");
        retryTimer = window.setTimeout(connect, 1500);
      };
      ws.onerror = () => {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      };
      ws.onmessage = (ev) => {
        try {
          const e = JSON.parse(ev.data);
          if (e.runId) {
            setRunId((prev) => {
              if (prev && prev !== e.runId) {
                // New run — reset all state so stale entries from the prior run disappear.
                const fresh: Record<string, CheckpointState> = {};
                for (const cp of PIPELINE)
                  fresh[cp.id] = { id: cp.id, status: "idle", retries: 0 };
                setStates(fresh);
                setLogsByCp({});
                setAllLogs([]);
                setRetries([]);
                setJourney([]);
                setArtifacts({});
                setPipelineStatus("idle");
                setAbortReason(null);
                setSavedRuns([]); // force the past-runs dropdown to re-fetch
              }
              return e.runId;
            });
          }
          const pushLog = (line: LogLine) => {
            setAllLogs((l) => [...l.slice(-1000), line]);
            if (line.checkpointId) {
              setLogsByCp((m) => ({
                ...m,
                [line.checkpointId!]: [
                  ...(m[line.checkpointId!] ?? []).slice(-500),
                  line,
                ],
              }));
            }
          };
          switch (e.type) {
            case "log":
              pushLog({
                ts: e.timestamp,
                checkpointId: e.checkpointId,
                msg: e.payload?.msg ?? "",
                level: e.payload?.level ?? "info",
              });
              break;
            case "checkpoint:status": {
              const newStatus = e.payload?.status;
              setStates((s) => {
                const prev = s[e.checkpointId] ?? { id: e.checkpointId, retries: 0, status: "idle" };
                if (newStatus === "running" || newStatus === "passed" || newStatus === "failed") {
                  setJourney((j) => [...j, {
                    kind: newStatus as JourneyEventKind,
                    checkpointId: e.checkpointId,
                    attempt: prev.retries,
                    ts: e.timestamp,
                  }]);
                }
                return {
                  ...s,
                  [e.checkpointId]: {
                    ...prev,
                    status: newStatus ?? "idle",
                    lastEventTs: e.timestamp,
                    waiting:
                      newStatus === "passed" || newStatus === "failed"
                        ? null
                        : (prev.waiting ?? null),
                  },
                };
              });
              if (newStatus === "running") {
                setPipelineStatus("running");
              }
              break;
            }
            case "checkpoint:retry":
              setRetries((r) => [
                ...r,
                {
                  checkpointId: e.checkpointId,
                  rollbackTo: e.payload?.rollbackTo,
                  attempt: e.payload?.attempt,
                  ts: e.timestamp,
                },
              ]);
              setJourney((j) => [...j, {
                kind: "rollback",
                checkpointId: e.checkpointId,
                rollbackTo: e.payload?.rollbackTo,
                attempt: e.payload?.attempt ?? 0,
                ts: e.timestamp,
              }]);
              setStates((s) => ({
                ...s,
                [e.checkpointId]: {
                  ...(s[e.checkpointId] ?? {
                    id: e.checkpointId,
                    retries: 0,
                    status: "failed",
                  }),
                  retries: e.payload?.attempt ?? 0,
                },
              }));
              break;
            case "human:waiting":
              setStates((s) => ({
                ...s,
                [e.checkpointId]: {
                  ...(s[e.checkpointId] ?? {
                    id: e.checkpointId,
                    retries: 0,
                    status: "running",
                  }),
                  status: "running",
                  waiting: { spec: e.payload?.spec },
                },
              }));
              break;
            case "artifact:update":
              if (e.payload?.artifacts && typeof e.payload.artifacts === "object") {
                setArtifacts((a) => ({ ...a, ...e.payload.artifacts }));
              }
              break;
            case "runs:list:response":
              setSavedRuns(e.payload?.runs ?? []);
              break;
            case "auto-mode:state":
              setAutoModeState({
                enabled: !!e.payload?.enabled,
                agentName: e.payload?.agentName,
              });
              break;
            case "human:rejected":
              setLastRejection({
                checkpointId: e.checkpointId,
                reason: e.payload?.reason ?? "unknown",
                ts: e.timestamp,
              });
              pushLog({
                ts: e.timestamp,
                checkpointId: e.checkpointId,
                msg: `Submission rejected: ${e.payload?.reason ?? "unknown"}`,
                level: "error",
              });
              break;
            case "human:resolved":
            case "task:accepted":
              setLastRejection(null);
              setStates((s) => ({
                ...s,
                [e.checkpointId]: {
                  ...(s[e.checkpointId] ?? {
                    id: e.checkpointId,
                    retries: 0,
                    status: "running",
                  }),
                  waiting: null,
                },
              }));
              if (e.type === "task:accepted" && e.payload?.task) {
                setArtifacts((a) => ({ ...a, task: e.payload.task }));
              }
              break;
            case "task:rejected":
              pushLog({
                ts: e.timestamp,
                checkpointId: "task",
                msg: `Task rejected: ${e.payload?.reason ?? ""}`,
                level: "error",
              });
              break;
            case "pipeline:complete":
              setPipelineStatus("complete");
              pushLog({
                ts: e.timestamp,
                msg: "Pipeline complete ✓",
                level: "success",
              });
              break;
            case "pipeline:abort":
              setPipelineStatus("aborted");
              setAbortReason(e.payload?.error ?? "unknown");
              pushLog({
                ts: e.timestamp,
                msg: `Pipeline aborted: ${e.payload?.error ?? ""}`,
                level: "error",
              });
              break;
          }
        } catch {
          /* ignore */
        }
      };
    };
    connect();
    return () => {
      cancelled = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      wsRef.current?.close();
    };
  }, [wsUrl]);

  const send = (type: string, payload?: unknown) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, payload }));
      return true;
    }
    return false;
  };

  return {
    runId,
    states,
    logsByCp,
    allLogs,
    retries,
    journey,
    artifacts,
    wsStatus,
    pipelineStatus,
    abortReason,
    savedRuns,
    lastRejection,
    autoMode,
    send,
  };
}
