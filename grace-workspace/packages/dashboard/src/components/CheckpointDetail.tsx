import { useState, useEffect, useRef } from "react";
import type { CheckpointState } from "../hooks/usePipeline";
import { PIPELINE } from "../hooks/usePipeline";
import { TaskForm, type SubmittedTask } from "./TaskForm";
import { ArtifactView } from "./ArtifactView";
import { HumanReview } from "./HumanReview";
import { DesignGatePrompt } from "./DesignGatePrompt";
import { ClarifyingQuestions } from "./ClarifyingQuestions";
import { LoadingState } from "./LoadingState";
import { RetryHistory, type RetryAttempt } from "./RetryHistory";
import { T } from "../theme";

const STATUS_BADGE: Record<string, { bg: string; fg: string; dot: string; label: string }> = {
  idle: { bg: T.codeBg, fg: T.textMuted, dot: T.textMuted, label: "Idle" },
  running: { bg: T.accentSoft, fg: T.accent, dot: T.accent, label: "Running" },
  passed: { bg: T.successSoft, fg: T.success, dot: T.success, label: "Passed" },
  failed: { bg: T.errorSoft, fg: T.error, dot: T.error, label: "Failed" },
  skipped: { bg: T.warnSoft, fg: T.warn, dot: T.warn, label: "Skipped" },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_BADGE[status] ?? STATUS_BADGE.idle!;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        background: s.bg,
        color: s.fg,
        padding: "5px 12px 5px 10px",
        borderRadius: 999,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 0.3,
      }}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: s.dot,
          animation: status === "running" ? "pulse 1.6s ease-in-out infinite" : undefined,
        }}
      />
      {s.label}
    </span>
  );
}

export function CheckpointDetail({
  checkpointId,
  state,
  artifacts,
  onSubmitTask,
  onHumanReviewRespond,
  onDesignGateRespond,
  onClarifyingAnswers,
  onRerunStep,
  lastRejection,
  wsConnected,
  runId,
}: {
  checkpointId: string;
  state: CheckpointState | undefined;
  artifacts: Record<string, unknown>;
  onSubmitTask: (task: SubmittedTask) => void;
  onHumanReviewRespond: (
    checkpointId: string,
    payload: {
      decision: "approve" | "edit" | "regenerate";
      editedSpec?: unknown;
      regeneratePrompt?: string;
      notes?: string;
    }
  ) => void;
  onDesignGateRespond: (payload: {
    designRequired: boolean;
    figmaUrl?: string;
    skipReason?: string;
  }) => void;
  onClarifyingAnswers: (payload: {
    answers: Record<string, string>;
    attachments: Record<string, Array<{ name: string; dataUrl: string }>>;
  }) => void;
  onRerunStep: (checkpointId: string) => void;
  lastRejection: { checkpointId: string; reason: string; ts: string } | null;
  wsConnected: boolean;
  runId: string | undefined;
}) {
  const meta = PIPELINE.find((p) => p.id === checkpointId);
  if (!meta || !state) {
    return <div style={{ color: T.textMuted, padding: 24 }}>Unknown checkpoint.</div>;
  }

  const artifactKey: Record<string, string> = {
    task: "task",
    product_alignment: "productAlignment",
    feature_research: "featureResearch",
    design_gate: "designGate",
    l2_planning: "l2",
    l2_review: "l2Review",
    l3_analysis: "l3",
    l3_review: "l3Review",
    implementation: "implementation",
    compiler: "compilationErrors",
    compiler_check: "compilerCheck",
    grpc_test: "grpcTest",
    design_match: "designDiff",
    cypress: "cypressReport",
    playwright: "playwrightReport",
    pr_review: "prReview",
    regression: "regression",
  };
  const aKey = artifactKey[checkpointId];
  const artifact = aKey ? artifacts[aKey] : undefined;

  // Retry history tracking
  // Store artifacts per retry attempt for this checkpoint
  const [retryArtifactHistory, setRetryArtifactHistory] = useState<Record<number, unknown>>({});
  const [selectedRetryAttempt, setSelectedRetryAttempt] = useState<number>(state.retries);
  const prevRetryRef = useRef<number>(state.retries);
  const lastArtifactForRetry = useRef<Record<number, unknown>>({});

  // Track artifacts for each retry attempt
  useEffect(() => {
    const currentRetry = state.retries;

    // Store artifact for current retry whenever we have one
    if (artifact !== undefined) {
      lastArtifactForRetry.current[currentRetry] = artifact;
    }

    // If retry increased, copy all previous artifacts to state
    if (currentRetry > prevRetryRef.current) {
      const newHistory: Record<number, unknown> = {};
      for (let i = 0; i < currentRetry; i++) {
        if (lastArtifactForRetry.current[i] !== undefined) {
          newHistory[i] = lastArtifactForRetry.current[i];
        }
      }
      setRetryArtifactHistory(newHistory);

      // Update selected to current if it was on old current
      if (selectedRetryAttempt >= currentRetry) {
        setSelectedRetryAttempt(currentRetry);
      }
    }

    prevRetryRef.current = currentRetry;
  }, [state.retries, artifact, selectedRetryAttempt]);

  // Clear history when checkpoint changes
  useEffect(() => {
    setRetryArtifactHistory({});
    setSelectedRetryAttempt(0);
    prevRetryRef.current = 0;
    lastArtifactForRetry.current = {};
  }, [checkpointId, runId]);

  // Build list of retry attempts for the dropdown
  const retryAttempts: RetryAttempt[] = (() => {
    const attempts: RetryAttempt[] = [];
    const currentRetry = state.retries;

    // Add all historical attempts from our stored history
    for (let i = 0; i < currentRetry; i++) {
      if (retryArtifactHistory[i] !== undefined) {
        attempts.push({
          attempt: i,
          status: "failed", // Historical attempts are always failed (otherwise no retry would happen)
          timestamp: new Date(Date.now() - (currentRetry - i) * 60000).toISOString(), // Estimate based on typical timing
        });
      }
    }

    // Add current attempt
    attempts.push({
      attempt: currentRetry,
      status: state.status === "running" ? "running" : state.status === "passed" ? "passed" : "failed",
      timestamp: new Date().toISOString(),
    });

    return attempts;
  })();

  // Get the artifact to display based on selected retry attempt
  const displayArtifact = selectedRetryAttempt === state.retries
    ? artifact
    : retryArtifactHistory[selectedRetryAttempt];

  const isTaskStep = checkpointId === "task";
  const isDesignGate = checkpointId === "design_gate";
  const isProductAlignment = checkpointId === "product_alignment";
  const taskAlreadySubmitted = !!artifacts.task;

  const pmWaiting = Boolean(
    isProductAlignment &&
      state.waiting &&
      Array.isArray((state.waiting.spec as any)?.questions)
  );

  // Treat the partial "pendingQuestions" artifact as not-yet-a-real-result,
  // so the loading card comes back while the PM re-runs with the answers.
  const artifactIsPartial =
    checkpointId === "product_alignment" &&
    artifact &&
    typeof artifact === "object" &&
    (artifact as any).pendingQuestions !== undefined;

  const showLoading = Boolean(
    state.status === "running" &&
      !state.waiting &&
      (artifact === undefined || artifactIsPartial)
  );
  const showGenericReview = Boolean(
    state.waiting && !isTaskStep && !isDesignGate && !pmWaiting
  );

  const globalIdx = PIPELINE.findIndex((p) => p.id === meta.id);

  return (
    <div style={{ padding: "28px 36px 36px", flex: 1, overflowY: "auto", minHeight: 0 }}>
      {/* Eyebrow */}
      <div
        style={{
          fontSize: 11,
          color: T.textSubtle,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: 1.2,
          marginBottom: 8,
        }}
      >
        Step {String(globalIdx + 1).padStart(2, "0")} ·{" "}
        {meta.type === "human" ? "Human gate" : "Automated"}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          marginBottom: 28,
          flexWrap: "wrap",
        }}
      >
        <h1
          style={{
            margin: 0,
            fontSize: 26,
            fontWeight: 700,
            color: T.text,
            letterSpacing: -0.3,
          }}
        >
          {meta.name}
        </h1>
        <StatusBadge status={state.status} />
        {state.retries > 0 && (
          <span
            style={{
              color: T.warn,
              fontSize: 11,
              fontWeight: 600,
              padding: "4px 10px",
              borderRadius: 999,
              background: T.warnSoft,
              textTransform: "uppercase",
              letterSpacing: 0.5,
            }}
          >
            retry {state.retries}
          </span>
        )}
        {runId && !isTaskStep && (
          <button
            onClick={() => {
              const msg =
                state.status === "running"
                  ? `Re-run "${meta.name}"? The current in-flight execution will be abandoned.`
                  : state.status === "passed"
                    ? `Re-run "${meta.name}"? Downstream stages will be reset.`
                    : `Re-run "${meta.name}"?`;
              if (window.confirm(msg)) onRerunStep(checkpointId);
            }}
            disabled={!wsConnected}
            title={
              wsConnected
                ? `Restart this run at "${meta.name}"`
                : "Engine is offline — cannot re-run"
            }
            style={{
              fontSize: 11,
              fontWeight: 600,
              padding: "5px 12px",
              borderRadius: 6,
              border: `1px solid ${T.accent}`,
              background: "transparent",
              color: T.accent,
              cursor: wsConnected ? "pointer" : "not-allowed",
              opacity: wsConnected ? 1 : 0.5,
              marginLeft: "auto",
            }}
          >
            ↻ Re-run this step
          </button>
        )}
      </div>

      {/* Retry History Selector - shown when there are retries */}
      {(state.retries > 0 || Object.keys(retryArtifactHistory).length > 0) && (
        <section style={{ marginBottom: 16 }}>
          <RetryHistory
            currentAttempt={state.retries}
            attempts={retryAttempts}
            selectedAttempt={selectedRetryAttempt}
            onSelectAttempt={setSelectedRetryAttempt}
            onBackToCurrent={() => setSelectedRetryAttempt(state.retries)}
          />
        </section>
      )}

      {isTaskStep && !taskAlreadySubmitted && (
        <section style={{ marginBottom: 32 }}>
          <SectionTitle>Submit task</SectionTitle>
          <div
            style={{
              color: T.textMuted,
              fontSize: 13,
              marginBottom: 12,
              maxWidth: 560,
            }}
          >
            Fill in the task below and hit submit. The pipeline will pick it up and
            advance to product alignment.
          </div>
          <TaskForm onSubmit={onSubmitTask} wsConnected={wsConnected} />
        </section>
      )}

      {state.waiting != null && isDesignGate ? (
        <section style={{ marginBottom: 32 }}>
          <SectionTitle>Design gate</SectionTitle>
          <DesignGatePrompt
            currentFigmaUrl={(state.waiting.spec as any)?.currentFigmaUrl}
            onRespond={onDesignGateRespond}
          />
        </section>
      ) : null}

      {pmWaiting && state.waiting != null ? (
        <section style={{ marginBottom: 32 }}>
          <SectionTitle>Clarifications needed</SectionTitle>
          <ClarifyingQuestions
            notes={(state.waiting.spec as any)?.notes}
            questions={(state.waiting.spec as any)?.questions ?? []}
            onSubmit={onClarifyingAnswers}
          />
        </section>
      ) : null}

      {showGenericReview && state.waiting ? (
        <section style={{ marginBottom: 32 }}>
          <SectionTitle>Review</SectionTitle>
          <HumanReview
            checkpointId={checkpointId}
            spec={state.waiting.spec}
            onRespond={(payload) => onHumanReviewRespond(checkpointId, payload)}
            rejectionReason={
              lastRejection && lastRejection.checkpointId === checkpointId
                ? lastRejection.reason
                : null
            }
          />
        </section>
      ) : null}

      {showLoading && (
        <section style={{ marginBottom: 32 }}>
          <LoadingState checkpointId={checkpointId} />
        </section>
      )}

      {displayArtifact !== undefined && !artifactIsPartial && (
        <section style={{ marginBottom: 32 }}>
          <SectionTitle>Result</SectionTitle>
          <ArtifactView checkpointId={checkpointId} artifact={displayArtifact} artifacts={artifacts} isRunning={state.status === "running"} />
        </section>
      )}

      {artifact === undefined &&
        !isTaskStep &&
        !isDesignGate &&
        !state.waiting &&
        state.status === "idle" && (
          <div
            style={{
              padding: "32px 20px",
              textAlign: "center",
              color: T.textSubtle,
              fontSize: 13,
              border: `1px dashed ${T.border}`,
              borderRadius: 10,
              maxWidth: 560,
            }}
          >
            This step hasn't run yet.
          </div>
        )}
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2
      style={{
        fontSize: 11,
        fontWeight: 700,
        color: T.textMuted,
        textTransform: "uppercase",
        letterSpacing: 0.8,
        margin: "0 0 10px 0",
      }}
    >
      {children}
    </h2>
  );
}
