import type { Checkpoint, DesignGateResult } from "../types.js";
import { ask, askYesNo } from "../prompts/cli-prompts.js";
import { autoDesignGate } from "../agents/auto-reviewer.js";

interface DesignGateResponse {
  designRequired: boolean;
  figmaUrl?: string;
  skipReason?: string;
}

export const designGateCheckpoint: Checkpoint = {
  id: "design_gate",
  name: "Design gate",
  description: "Ask whether UI design is needed and capture a Figma URL if so.",
  retryFrom: "design_gate",
  timeout: 24 * 60 * 60 * 1000,
  async run(ctx) {
    // Auto mode: reviewer agent decides.
    if (ctx.options.autoMode) {
      try {
        const decision = await autoDesignGate(ctx);
        const gate: DesignGateResult = decision.designRequired
          ? {
              designRequired: true,
              figmaReady: !!decision.figmaUrl,
              figmaUrl: decision.figmaUrl,
            }
          : {
              designRequired: false,
              figmaReady: false,
              skipReason: decision.skipReason,
            };
        return { passed: true, artifacts: { designGate: gate } };
      } catch (err) {
        ctx.log(
          `auto-reviewer failed, falling back: ${err instanceof Error ? err.message : String(err)}`,
          "warn"
        );
      }
    }

    // CI mode: infer from the task definition and pass through.
    if (ctx.options.autoApproveReviews) {
      const url = ctx.artifacts.task?.figmaUrl;
      const gate: DesignGateResult = url
        ? { designRequired: true, figmaReady: true, figmaUrl: url }
        : {
            designRequired: false,
            figmaReady: false,
            skipReason: "auto-approved — no figmaUrl in task",
          };
      return { passed: true, artifacts: { designGate: gate } };
    }

    // UI mode: wait for dashboard to answer.
    if (ctx.options.taskFromUi && ctx.bus) {
      ctx.log(
        "[design_gate] ⏳ Awaiting decision from the dashboard: does this task need UI design?",
        "warn"
      );
      ctx.bus.emitHumanWaiting("design_gate", {
        question: "Does this task require UI design?",
        currentFigmaUrl: ctx.artifacts.task?.figmaUrl,
      });

      while (true) {
        const response = await ctx.bus.waitFor<DesignGateResponse>(
          "human:design_gate"
        );
        if (typeof response.designRequired !== "boolean") {
          ctx.bus.emit("human:rejected", "design_gate", {
            reason: "designRequired must be a boolean",
          });
          continue;
        }
        if (response.designRequired) {
          const url = response.figmaUrl?.trim();
          if (!url || !/^https?:\/\/(www\.)?figma\.com\//.test(url)) {
            ctx.bus.emit("human:rejected", "design_gate", {
              reason: "A valid figma.com URL is required when design is needed",
            });
            continue;
          }
          const gate: DesignGateResult = {
            designRequired: true,
            figmaReady: true,
            figmaUrl: url,
          };
          ctx.log(`[design_gate] ✓ Design required (figma: ${url})`, "success");
          ctx.bus.emit("human:resolved", "design_gate", {
            decision: "design_required",
          });
          return { passed: true, artifacts: { designGate: gate } };
        }
        const gate: DesignGateResult = {
          designRequired: false,
          figmaReady: false,
          skipReason: response.skipReason?.trim() || "Reviewer said no design needed",
        };
        ctx.log(
          `[design_gate] ✓ No design needed: ${gate.skipReason}`,
          "success"
        );
        ctx.bus.emit("human:resolved", "design_gate", {
          decision: "no_design",
        });
        return { passed: true, artifacts: { designGate: gate } };
      }
    }

    // CLI fallback
    const needsDesign = await askYesNo("Does this task require UI design?", true);
    if (!needsDesign) {
      const reason = await ask("Reason for skipping design gate: ");
      return {
        passed: true,
        artifacts: {
          designGate: {
            designRequired: false,
            figmaReady: false,
            skipReason: reason || "not required",
          } satisfies DesignGateResult,
        },
      };
    }
    let url = ctx.artifacts.task?.figmaUrl;
    if (!url) url = await ask("Figma URL: ");
    if (!/^https?:\/\/(www\.)?figma\.com\//.test(url)) {
      return { passed: false, errors: [`Invalid Figma URL: ${url}`] };
    }
    return {
      passed: true,
      artifacts: {
        designGate: {
          designRequired: true,
          figmaReady: true,
          figmaUrl: url,
        } satisfies DesignGateResult,
      },
    };
  },
};
