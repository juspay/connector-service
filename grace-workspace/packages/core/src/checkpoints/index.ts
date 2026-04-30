import type { Checkpoint } from "../types.js";
import { taskCheckpoint } from "./task.js";
import { preflightCheckpoint } from "./preflight.js";
import { l2PlanningCheckpoint } from "./l2-planning.js";
import { l2ReviewCheckpoint } from "./l2-review.js";
import { l3AnalysisCheckpoint } from "./l3-analysis.js";
import { l3ReviewCheckpoint } from "./l3-review.js";
import { implementationCheckpoint } from "./implementation.js";
import { compilerCheckpoint } from "./compiler.js";
import { designMatchCheckpoint } from "./design-match.js";
import { cypressCheckpoint } from "./cypress.js";
import { playwrightCheckpoint } from "./playwright.js";
import { prReviewCheckpoint } from "./pr-review.js";
import { regressionCheckpoint } from "./regression.js";

// Grace 2.3_codegen.md workflow: task → preflight → L2_planning → L3_analysis → implementation
export const ALL_CHECKPOINTS: Checkpoint[] = [
  taskCheckpoint,
  preflightCheckpoint,
  l2PlanningCheckpoint,
  l2ReviewCheckpoint,
  l3AnalysisCheckpoint,
  l3ReviewCheckpoint,
  implementationCheckpoint,
  compilerCheckpoint,
  designMatchCheckpoint,
  cypressCheckpoint,
  playwrightCheckpoint,
  prReviewCheckpoint,
  regressionCheckpoint,
];
