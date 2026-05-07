import {
  type Checkpoint,
  type CheckpointId,
  type CheckpointResult,
  PipelineAbortError,
  type PipelineContext,
} from "./types.js";
import type { StateManager } from "./state.js";
import { withTimeout } from "./utils.js";
import type { PipelineEventBus } from "./logger.js";

export class PipelineEngine {
  constructor(
    private checkpoints: Checkpoint[],
    private state: StateManager,
    private bus?: PipelineEventBus
  ) {}

  async run(ctx: PipelineContext, startFrom?: CheckpointId): Promise<void> {
    let i = startFrom
      ? this.checkpoints.findIndex((c) => c.id === startFrom)
      : 0;
    if (i === -1) throw new Error(`Unknown checkpoint: ${startFrom}`);

    while (i < this.checkpoints.length) {
      const checkpoint = this.checkpoints[i]!;
      const retries = ctx.retryCount[checkpoint.id] ?? 0;
      const maxRetries = checkpoint.maxRetries ?? ctx.options.maxRetries ?? 3;

      if (retries >= maxRetries) {
        if (checkpoint.continueOnFailure) {
          // Graceful degradation: accept failure and continue to next checkpoint
          ctx.log(
            `[${checkpoint.id}] Max retries (${maxRetries}) exceeded. Continuing to next checkpoint (continueOnFailure=true).`,
            "warn"
          );
          await this.state.save(ctx, checkpoint.id, "failed");
          this.bus?.emitStatus(checkpoint.id, "failed");
          i++; // Continue to next checkpoint instead of aborting
          continue;
        }

        ctx.log(
          `[${checkpoint.id}] Max retries (${maxRetries}) exceeded. Pausing for manual retry.`,
          "error"
        );
        await this.state.save(ctx, checkpoint.id, "waiting_for_retry");
        this.bus?.emitStatus(checkpoint.id, "waiting_for_retry");
        this.bus?.emit("pipeline:waiting_for_retry", checkpoint.id, {
          maxRetries,
          lastError: "Max retries exceeded",
        });
        throw new PipelineAbortError(checkpoint.id, "Max retries exceeded - manual retry required");
      }

      ctx.log(`[${checkpoint.id}] Starting: ${checkpoint.name}`, "info");
      this.bus?.emitCheckpoint("checkpoint:start", checkpoint.id, { retries });
      this.bus?.emitStatus(checkpoint.id, "running");
      await this.state.save(ctx, checkpoint.id, "running");

      const startedAt = Date.now();
      let result: CheckpointResult;
      try {
        result = await withTimeout(
          checkpoint.run(ctx),
          checkpoint.timeout ?? 120_000,
          checkpoint.id
        );
      } catch (err) {
        result = {
          passed: false,
          errors: [err instanceof Error ? err.message : String(err)],
        };
      }

      // Always emit a single, unified artifact:update on completion — even
      // when the checkpoint produced no `result.artifacts`. The dashboard
      // uses this as the per-attempt history record (status + errors +
      // output, with artifacts when available); silently dropping the event
      // for failure-with-no-artifacts cases is what made retry pages empty.
      const emitAttemptUpdate = () => {
        this.bus?.emit("artifact:update", checkpoint.id, {
          artifacts: result.artifacts ?? {},
          retryAttempt: retries,
          status: result.passed ? "passed" : "failed",
          errors: result.errors ?? [],
          output: result.output ?? null,
        });
      };

      if (result.passed) {
        if (result.artifacts) {
          Object.assign(ctx.artifacts, result.artifacts);
        }
        emitAttemptUpdate();
        ctx.log(`[${checkpoint.id}] ✓ Passed`, "success");
        this.bus?.emitCheckpoint("checkpoint:pass", checkpoint.id);
        this.bus?.emitStatus(checkpoint.id, "passed");
        await this.state.save(ctx, checkpoint.id, "passed");
        await this.state.saveAttempt(
          ctx.runId,
          checkpoint.id,
          retries,
          "passed",
          null,
          result.output ?? null,
          result.artifacts ?? null,
          startedAt,
          Date.now()
        );
        i++;
      } else {
        ctx.log(
          `[${checkpoint.id}] ✕ Failed: ${result.errors?.join("; ") ?? "unknown"}`,
          "error"
        );
        this.bus?.emitCheckpoint("checkpoint:fail", checkpoint.id, {
          errors: result.errors,
        });
        this.bus?.emitStatus(checkpoint.id, "failed");

        // Preserve partial artifacts from the failed run (e.g. implementation
        // files that were written before the failure) so retries can resume.
        if (result.artifacts) {
          Object.assign(ctx.artifacts, result.artifacts);
        }
        emitAttemptUpdate();

        await this.state.save(ctx, checkpoint.id, "failed");
        await this.state.saveAttempt(
          ctx.runId,
          checkpoint.id,
          retries,
          "failed",
          result.errors ?? null,
          result.output ?? null,
          result.artifacts ?? null,
          startedAt,
          Date.now()
        );

        if (checkpoint.onFail) {
          ctx.log(`[${checkpoint.id}] Running failure handler...`, "info");
          try {
            await checkpoint.onFail(ctx, result);
          } catch (err) {
            ctx.log(
              `[${checkpoint.id}] onFail handler threw: ${err instanceof Error ? err.message : String(err)}`,
              "warn"
            );
          }
        }

        // Determine retry target - for grpc_test checkpoint with timeout errors,
        // retry only the grpc_test checkpoint itself instead of rolling back to implementation
        const isTimeoutError = result.errors?.some(
          (e) => e.includes("timed out") || e.includes("timeout")
        );
        const effectiveRetryFrom =
          checkpoint.id === "grpc_test" && isTimeoutError
            ? "grpc_test" // Timeout: retry only grpc_test, don't rebuild
            : checkpoint.retryFrom;

        const retryIdx = this.checkpoints.findIndex(
          (c) => c.id === effectiveRetryFrom
        );
        if (retryIdx === -1) {
          throw new PipelineAbortError(
            checkpoint.id,
            `Unknown retryFrom target: ${effectiveRetryFrom}`
          );
        }
        ctx.log(
          `[${checkpoint.id}] Rolling back to: ${effectiveRetryFrom} (retry ${retries + 1}/${maxRetries})`,
          "warn"
        );
        this.bus?.emitCheckpoint("checkpoint:retry", checkpoint.id, {
          rollbackTo: effectiveRetryFrom,
          attempt: retries + 1,
        });

        ctx.retryCount[checkpoint.id] = retries + 1;

        for (let j = retryIdx; j <= i; j++) {
          const cpId = this.checkpoints[j]!.id;
          if (cpId !== checkpoint.id) {
            await this.state.save(ctx, cpId, "idle");
            this.bus?.emitStatus(cpId, "idle");
          }
        }
        i = retryIdx;
      }
    }

    ctx.log("Pipeline complete. All checkpoints passed.", "success");
    this.bus?.emit("pipeline:complete");
  }
}
