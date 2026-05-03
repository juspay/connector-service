import type { Checkpoint, L2Plan, L2GenerationLog } from "../types.js";
import { runAI } from "../tools/runner-factory.js";
import { L2_SYSTEM, buildL2User } from "../generators/l2-prompt.js";
import {
  LINKS_AGENT_SYSTEM,
  buildLinksAgentUserPayload,
  type LinksAgentResult,
} from "../generators/links-agent-prompt.js";
import {
  TECHSPEC_AGENT_SYSTEM,
  buildTechspecAgentUserPayload,
  type TechspecAgentResult,
} from "../generators/techspec-agent-prompt.js";
import { parseTechspecToL2 } from "../generators/techspec-parser.js";

function valid(spec: unknown): spec is L2Plan {
  if (!spec || typeof spec !== "object") return false;
  const s = spec as Record<string, unknown>;

  // Basic validation
  const basicValid =
    typeof s.summary === "string" &&
    typeof s.scope === "string" &&
    typeof s.outOfScope === "string" &&
    Array.isArray(s.technicalConstraints) &&
    typeof s.estimatedComplexity === "string" &&
    ["low", "medium", "high"].includes(s.estimatedComplexity as string);

  if (!basicValid) return false;

  // Validate specContent exists and has 8 sections
  const specContent = s.specContent;
  if (!specContent || typeof specContent !== "string") {
    return false;
  }

  // Check for all 8 required sections in specContent
  const requiredSections = [
    "Connector Profile",
    "Authentication",
    "Supported Flows",
    "Request Schema",
    "Response Schema",
    "Error Handling",
    "Webhooks",
    "References",
  ];

  const missingSections = requiredSections.filter(
    (section) => !specContent.includes(section)
  );

  if (missingSections.length > 0) {
    return false;
  }

  // Validate researchFindings has connectorDocs with verification scores
  const researchFindings = s.researchFindings;
  if (researchFindings && typeof researchFindings === "object") {
    const rf = researchFindings as Record<string, unknown>;
    const connectorDocs = rf.connectorDocs;
    if (Array.isArray(connectorDocs)) {
      for (const doc of connectorDocs) {
        if (doc && typeof doc === "object") {
          const d = doc as Record<string, unknown>;
          // verificationScore and verificationStatus are now required
          if (typeof d.verificationScore !== "number") {
            return false;
          }
          if (!["valid", "problematic", "insufficient"].includes(d.verificationStatus as string)) {
            return false;
          }
        }
      }
    }
  }

  return true;
}

export const l2PlanningCheckpoint: Checkpoint = {
  id: "l2_planning",
  name: "L2 Planning",
  description: "Generate technical specification via documentation discovery and tech spec generation (2.1_links.md + 2.2_techspec.md).",
  retryFrom: "l2_planning",
  timeout: 45 * 60 * 1000, // 45 min (includes grace techspec ~20 min)
  async run(ctx) {
    if (!ctx.artifacts.task) {
      return { passed: false, errors: ["Missing task artifact"] };
    }

    const task = ctx.artifacts.task;
    const connector = task.targetConnectors?.[0] || "Unknown";
    const paymentMethod = task.paymentMethod || "Unknown";
    const projectRoot = task.projectRoot;

    // Initialize generation log
    const generationLog: L2GenerationLog = {
      workflowExecutions: [],
      webSearchQueries: [],
      filesCreated: [],
      commandsExecuted: [],
    };

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: Links Agent - Discover documentation URLs
    // ═══════════════════════════════════════════════════════════════════════
    ctx.log("[l2_planning] ╔═══════════════════════════════════════════════════════╗", "info");
    ctx.log("[l2_planning] ║  PHASE 1: Links Discovery                              ║", "info");
    ctx.log("[l2_planning] ╚═══════════════════════════════════════════════════════╝", "info");
    ctx.log("[l2_planning] 📖 Reading workflow: grace/workflow/2.1_links.md", "info");

    const linksPayload = buildLinksAgentUserPayload(connector, paymentMethod, task);
    let linksResult: LinksAgentResult;

    try {
      const rawResult = await runAI<LinksAgentResult>({
        skillBody: LINKS_AGENT_SYSTEM,
        userPayload: linksPayload,
        cwd: projectRoot,
        label: "l2_gen:links",
        timeoutMs: 15 * 60 * 1000, // 15 min for web search
      });
      linksResult = rawResult;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[l2_planning] Links Agent failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Links discovery failed: ${msg}`],
        artifacts: { l2GenLog: generationLog },
      };
    }

    // Log workflow execution
    if (linksResult.executionLog) {
      generationLog.workflowExecutions.push({
        phase: "links_discovery",
        workflowFile: linksResult.executionLog.workflowFile || "grace/workflow/2.1_links.md",
        readAt: new Date().toISOString(),
        output: `Found ${linksResult.urlCount} URLs for ${linksResult.connector}`,
        status: linksResult.success ? "success" : "failed",
      });

      // Log web search queries
      if (linksResult.executionLog.webSearchQueries) {
        ctx.log("[l2_planning] 🔍 Web search queries executed:", "info");
        for (const query of linksResult.executionLog.webSearchQueries) {
          generationLog.webSearchQueries.push({
            query: query.query,
            timestamp: query.timestamp,
            results: query.results || [],
            resultCount: query.resultCount || query.results?.length || 0,
          });
          ctx.log(`[l2_planning]    "${query.query}" → ${query.resultCount || query.results?.length || 0} results`, "info");

          // Log first 3 URLs from each query
          const topResults = (query.results || []).slice(0, 3);
          for (const result of topResults) {
            ctx.log(`[l2_planning]       └─ ${result.url}`, "info");
          }
        }
      }

      // Log files created
      if (linksResult.executionLog.filesCreated) {
        for (const file of linksResult.executionLog.filesCreated) {
          generationLog.filesCreated.push(file);
          ctx.log(`[l2_planning] 📝 Created: ${file.path} (${file.description})`, "success");
        }
      }
    }

    if (!linksResult.success) {
      ctx.log("[l2_planning] Links discovery failed", "error");
      return {
        passed: false,
        errors: ["Links discovery failed"],
        artifacts: { l2GenLog: generationLog },
      };
    }

    ctx.log(`[l2_planning] ✓ Phase 1 complete: ${linksResult.urlCount} URLs discovered`, "success");

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: Tech Spec Agent - Generate spec via grace CLI
    // ═══════════════════════════════════════════════════════════════════════
    ctx.log("[l2_planning] ╔═══════════════════════════════════════════════════════╗", "info");
    ctx.log("[l2_planning] ║  PHASE 2: Techspec Generation                          ║", "info");
    ctx.log("[l2_planning] ╚═══════════════════════════════════════════════════════╝", "info");
    ctx.log("[l2_planning] 📖 Reading workflow: grace/workflow/2.2_techspec.md", "info");
    ctx.log(`[l2_planning] ⚙️  Running grace techspec for ${connector}...`, "info");
    ctx.log("[l2_planning]    (This may take 15-25 minutes)", "warn");

    const techspecPayload = buildTechspecAgentUserPayload(connector, paymentMethod, task);
    let techspecResult: TechspecAgentResult;

    try {
      const rawResult = await runAI<TechspecAgentResult>({
        skillBody: TECHSPEC_AGENT_SYSTEM,
        userPayload: techspecPayload,
        cwd: projectRoot,
        label: "l2_gen:techspec",
        timeoutMs: 30 * 60 * 1000, // 30 min for grace techspec
      });
      techspecResult = rawResult;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[l2_planning] Tech Spec Agent failed: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Tech spec generation failed: ${msg}`],
        artifacts: { l2GenLog: generationLog },
      };
    }

    // Normalize specPath if missing
    const specPath = techspecResult.specPath || `techspecs/${connector}_${paymentMethod}_spec.md`;

    // Normalize commands to object format (handle strings from agent)
    const normalizeCommand = (cmd: unknown): { command: string; workingDir: string; output?: string; durationMs?: number; status: "success" | "failed" } => {
      if (typeof cmd === "string") {
        return {
          command: cmd,
          workingDir: projectRoot,
          output: "",
          durationMs: 0,
          status: "success",
        };
      }
      if (cmd && typeof cmd === "object") {
        const c = cmd as Record<string, unknown>;
        return {
          command: String(c.command || ""),
          workingDir: String(c.workingDir || projectRoot),
          output: c.output ? String(c.output) : undefined,
          durationMs: typeof c.durationMs === "number" ? c.durationMs : undefined,
          status: (c.status === "failed" ? "failed" : "success") as "success" | "failed",
        };
      }
      return { command: "", workingDir: projectRoot, status: "success" };
    };

    // Log workflow execution
    if (techspecResult.executionLog) {
      generationLog.workflowExecutions.push({
        phase: "techspec_generation",
        workflowFile: techspecResult.executionLog.workflowFile || "grace/workflow/2.2_techspec.md",
        readAt: new Date().toISOString(),
        output: `Generated spec at ${specPath}`,
        status: techspecResult.success ? "success" : "failed",
      });

      // Log commands executed
      if (techspecResult.executionLog.commandsExecuted) {
        ctx.log("[l2_planning] ⚙️  Commands executed:", "info");
        for (const rawCmd of techspecResult.executionLog.commandsExecuted) {
          const cmd = normalizeCommand(rawCmd);
          if (cmd.command) { // Only add non-empty commands
            generationLog.commandsExecuted.push(cmd);
            ctx.log(`[l2_planning]    $ ${cmd.command}`, "info");
            ctx.log(
              `         CWD: ${cmd.workingDir} | Status: ${cmd.status} | Duration: ${
                cmd.durationMs ? `${(cmd.durationMs / 1000).toFixed(1)}s` : "unknown"
              }`,
              cmd.status === "success" ? "success" : "error"
            );
          }
        }
      }

      // Log files created
      if (techspecResult.executionLog.filesCreated) {
        for (const file of techspecResult.executionLog.filesCreated) {
          // Avoid duplicating the URLs file that was already logged
          if (!generationLog.filesCreated.some(f => f.path === file.path)) {
            generationLog.filesCreated.push(file);
          }
          ctx.log(`[l2_planning] 📄 ${file.path} (${file.description})`, "success");
        }
      }
    }

    if (!techspecResult.success) {
      ctx.log("[l2_planning] Tech spec generation failed", "error");
      return {
        passed: false,
        errors: ["Tech spec generation failed"],
        artifacts: { l2GenLog: generationLog },
      };
    }

    ctx.log(`[l2_planning] ✓ Phase 2 complete: Spec generated at ${techspecResult.specPath}`, "success");

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 3: Parse techspec into L2Spec format
    // ═══════════════════════════════════════════════════════════════════════
    ctx.log("[l2_planning] Parsing techspec into L2Spec format...", "info");

    let l2Plan: L2Plan;
    try {
      l2Plan = parseTechspecToL2(techspecResult.specContent, connector, paymentMethod);
      l2Plan.generationLog = generationLog;
      // Store full tech spec content for display in UI
      l2Plan.specContent = techspecResult.specContent;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      ctx.log(`[l2_planning] Failed to parse techspec: ${msg}`, "error");
      return {
        passed: false,
        errors: [`Failed to parse techspec: ${msg}`],
        artifacts: { l2GenLog: generationLog },
      };
    }

    // Validate the parsed spec
    if (!valid(l2Plan)) {
      return {
        passed: false,
        errors: ["Parsed L2 plan failed validation"],
        artifacts: { l2: l2Plan, l2GenLog: generationLog },
      };
    }

    // Clear any regenerate prompt now that we've acted on it
    delete ctx.artifacts.l2RegeneratePrompt;

    // Final summary log
    ctx.log("[l2_planning] ╔═══════════════════════════════════════════════════════╗", "success");
    ctx.log("[l2_planning] ║  L2 Planning Complete                                 ║", "success");
    ctx.log("[l2_planning] ╚═══════════════════════════════════════════════════════╝", "success");
    ctx.log(`[l2_planning] Summary: ${l2Plan.summary.slice(0, 80)}...`, "success");
    ctx.log(`[l2_planning] Complexity: ${l2Plan.estimatedComplexity}`, "info");
    ctx.log(`[l2_planning] URLs discovered: ${generationLog.webSearchQueries.reduce((sum, q) => sum + q.resultCount, 0)}`, "info");
    ctx.log(`[l2_planning] Commands executed: ${generationLog.commandsExecuted.length}`, "info");

    return {
      passed: true,
      artifacts: {
        l2: l2Plan,
        l2GenLog: generationLog,
      },
    };
  },
};
