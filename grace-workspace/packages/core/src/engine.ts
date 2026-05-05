import { createHash } from "node:crypto";
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

/**
 * Fingerprint a checkpoint failure so the engine can detect identical-error
 * loops. Normalised to ignore whitespace, timestamps, and pid noise so two
 * structurally identical failures fingerprint the same.
 */
function fingerprintFailure(result: CheckpointResult): string | null {
  if (!result.errors || result.errors.length === 0) return null;
  const normalised = result.errors
    .join("|")
    .replace(/\s+/g, " ")
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, "<ts>")
    .replace(/\bpid[=:]?\s*\d+/gi, "pid=<n>")
    .slice(0, 500);
  return createHash("sha1").update(normalised).digest("hex");
}

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

      if (result.passed) {
        if (result.artifacts) {
          Object.assign(ctx.artifacts, result.artifacts);
          // Push each artifact key to the dashboard so it can render per-checkpoint results.
          this.bus?.emit("artifact:update", checkpoint.id, {
            artifacts: result.artifacts,
          });
        }
        ctx.log(`[${checkpoint.id}] ✓ Passed`, "success");
        this.bus?.emitCheckpoint("checkpoint:pass", checkpoint.id);
        this.bus?.emitStatus(checkpoint.id, "passed");
        await this.state.save(ctx, checkpoint.id, "passed");
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
          this.bus?.emit("artifact:update", checkpoint.id, {
            artifacts: result.artifacts,
          });
        }

        // ── Identical-error guard (engine-level 3-strike rule) ────────────
        // GRACE 2.3.md mandates a 3-strike rule on identical errors. Enforce
        // it at the engine so an LLM-driven checkpoint cannot rationalise
        // its way past it. Two consecutive identical fingerprints from the
        // same checkpoint = the rollback target's fix did not address the
        // failure — escalate or abort.
        ctx.errorFingerprints ??= {};
        const fp = fingerprintFailure(result);
        const history = ctx.errorFingerprints[checkpoint.id] ?? [];
        const lastFp = history[history.length - 1];
        if (fp && lastFp === fp) {
          ctx.log(
            `[${checkpoint.id}] Identical error repeated (fp=${fp.slice(0, 8)}). The previous rollback did not change the failure — aborting before burning more retries.`,
            "error",
          );
          await this.state.save(ctx, checkpoint.id, "waiting_for_retry");
          this.bus?.emitStatus(checkpoint.id, "waiting_for_retry");
          this.bus?.emit("pipeline:waiting_for_retry", checkpoint.id, {
            maxRetries,
            lastError: "Identical error repeated — manual intervention required",
          });
          throw new PipelineAbortError(
            checkpoint.id,
            `Identical error fingerprint (${fp.slice(0, 8)}) on consecutive attempts — code repair did not address the failure. Manual intervention required.`,
          );
        }
        if (fp) {
          ctx.errorFingerprints[checkpoint.id] = [...history, fp].slice(-3);
        }

        await this.state.save(ctx, checkpoint.id, "failed");

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

        const retryIdx = this.checkpoints.findIndex(
          (c) => c.id === checkpoint.retryFrom
        );
        if (retryIdx === -1) {
          throw new PipelineAbortError(
            checkpoint.id,
            `Unknown retryFrom target: ${checkpoint.retryFrom}`
          );
        }
        ctx.log(
          `[${checkpoint.id}] Rolling back to: ${checkpoint.retryFrom} (retry ${retries + 1}/${maxRetries})`,
          "warn"
        );
        this.bus?.emitCheckpoint("checkpoint:retry", checkpoint.id, {
          rollbackTo: checkpoint.retryFrom,
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
