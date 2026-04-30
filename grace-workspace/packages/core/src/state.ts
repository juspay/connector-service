import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";
import type {
  CheckpointId,
  CheckpointStatus,
  PipelineContext,
  TaskDefinition,
} from "./types.js";

export interface SavedState {
  runId: string;
  task: TaskDefinition;
  artifacts: Record<string, unknown>;
  retryCount: Record<string, number>;
  checkpointStates: Record<string, CheckpointStatus>;
}

export interface RunSummary {
  runId: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  lastCheckpoint?: CheckpointId;
  lastStatus?: CheckpointStatus;
}

export interface CheckpointHistory {
  checkpointId: CheckpointId;
  status: CheckpointStatus;
  updatedAt: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  task_json TEXT NOT NULL,
  artifacts_json TEXT NOT NULL,
  retry_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoint_states (
  run_id TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL,
  status TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (run_id, checkpoint_id)
);
`;

export class StateManager {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const p =
      dbPath ??
      path.join(process.env.HOME ?? ".", ".byne", "pipeline.sqlite");
    fs.mkdirSync(path.dirname(p), { recursive: true });
    this.db = new Database(p);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  async save(
    ctx: PipelineContext,
    checkpointId: CheckpointId,
    status: CheckpointStatus
  ): Promise<void> {
    const now = Date.now();
    const upsertRun = this.db.prepare(`
      INSERT INTO runs (run_id, task_json, artifacts_json, retry_json, created_at, updated_at)
      VALUES (@run_id, @task_json, @artifacts_json, @retry_json, @created_at, @updated_at)
      ON CONFLICT(run_id) DO UPDATE SET
        task_json = excluded.task_json,
        artifacts_json = excluded.artifacts_json,
        retry_json = excluded.retry_json,
        updated_at = excluded.updated_at
    `);
    upsertRun.run({
      run_id: ctx.runId,
      task_json: JSON.stringify(ctx.task),
      artifacts_json: JSON.stringify(ctx.artifacts),
      retry_json: JSON.stringify(ctx.retryCount),
      created_at: now,
      updated_at: now,
    });

    const upsertCp = this.db.prepare(`
      INSERT INTO checkpoint_states (run_id, checkpoint_id, status, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(run_id, checkpoint_id) DO UPDATE SET
        status = excluded.status,
        updated_at = excluded.updated_at
    `);
    upsertCp.run(ctx.runId, checkpointId, status, now);
  }

  async load(runId: string): Promise<SavedState | null> {
    const row = this.db
      .prepare(`SELECT * FROM runs WHERE run_id = ?`)
      .get(runId) as
      | {
          run_id: string;
          task_json: string;
          artifacts_json: string;
          retry_json: string;
        }
      | undefined;
    if (!row) return null;

    const cpRows = this.db
      .prepare(
        `SELECT checkpoint_id, status FROM checkpoint_states WHERE run_id = ?`
      )
      .all(runId) as { checkpoint_id: string; status: CheckpointStatus }[];
    const checkpointStates: Record<string, CheckpointStatus> = {};
    for (const r of cpRows) checkpointStates[r.checkpoint_id] = r.status;

    return {
      runId: row.run_id,
      task: JSON.parse(row.task_json),
      artifacts: JSON.parse(row.artifacts_json),
      retryCount: JSON.parse(row.retry_json),
      checkpointStates,
    };
  }

  async listRuns(): Promise<RunSummary[]> {
    const rows = this.db
      .prepare(
        `SELECT run_id, task_json, created_at, updated_at FROM runs ORDER BY updated_at DESC`
      )
      .all() as {
      run_id: string;
      task_json: string;
      created_at: number;
      updated_at: number;
    }[];
    return rows.map((r) => {
      const task = JSON.parse(r.task_json) as TaskDefinition;
      const last = this.db
        .prepare(
          `SELECT checkpoint_id, status FROM checkpoint_states WHERE run_id = ? ORDER BY updated_at DESC LIMIT 1`
        )
        .get(r.run_id) as
        | { checkpoint_id: CheckpointId; status: CheckpointStatus }
        | undefined;
      return {
        runId: r.run_id,
        title: task.title ?? "(untitled)",
        createdAt: r.created_at,
        updatedAt: r.updated_at,
        lastCheckpoint: last?.checkpoint_id,
        lastStatus: last?.status,
      };
    });
  }

  /**
   * Rewind a run: delete saved checkpoint_states rows for the given stages
   * (so the dashboard shows them as idle on reconnect) and overwrite the
   * stored artifacts/retry-counts with the cleaned versions from memory.
   * Used by the resume flow when the user re-runs from a specific step.
   */
  async rewindRun(
    runId: string,
    artifacts: Record<string, unknown>,
    retryCount: Record<string, number>,
    clearedStages: CheckpointId[]
  ): Promise<void> {
    const delStmt = this.db.prepare(
      `DELETE FROM checkpoint_states WHERE run_id = ? AND checkpoint_id = ?`
    );
    const tx = this.db.transaction(() => {
      for (const id of clearedStages) delStmt.run(runId, id);
      this.db
        .prepare(
          `UPDATE runs
             SET artifacts_json = @artifacts_json,
                 retry_json     = @retry_json,
                 updated_at     = @updated_at
           WHERE run_id = @run_id`
        )
        .run({
          run_id: runId,
          artifacts_json: JSON.stringify(artifacts),
          retry_json: JSON.stringify(retryCount),
          updated_at: Date.now(),
        });
    });
    tx();
  }

  async getCheckpointHistory(runId: string): Promise<CheckpointHistory[]> {
    const rows = this.db
      .prepare(
        `SELECT checkpoint_id, status, updated_at FROM checkpoint_states WHERE run_id = ? ORDER BY updated_at ASC`
      )
      .all(runId) as {
      checkpoint_id: CheckpointId;
      status: CheckpointStatus;
      updated_at: number;
    }[];
    return rows.map((r) => ({
      checkpointId: r.checkpoint_id,
      status: r.status,
      updatedAt: r.updated_at,
    }));
  }

  /**
   * Remove runs that are *clearly* abandoned scaffolding:
   *  - empty / missing task title AND no passed checkpoint
   * A run with a real title OR at least one passed stage is preserved,
   * even if it was later abandoned — those represent real progress.
   */
  async pruneEmptyRuns(): Promise<number> {
    const rows = this.db
      .prepare(`SELECT run_id, task_json FROM runs`)
      .all() as { run_id: string; task_json: string }[];
    let removed = 0;
    const deleteRun = this.db.prepare(`DELETE FROM runs WHERE run_id = ?`);
    const deleteStates = this.db.prepare(
      `DELETE FROM checkpoint_states WHERE run_id = ?`
    );
    const anyPassed = this.db.prepare(
      `SELECT 1 FROM checkpoint_states WHERE run_id = ? AND status = 'passed' LIMIT 1`
    );
    for (const r of rows) {
      let title = "";
      try {
        const t = JSON.parse(r.task_json) as { title?: string };
        title = t.title?.trim() ?? "";
      } catch {
        continue;
      }
      const hasPassed = anyPassed.get(r.run_id);
      if (!title && !hasPassed) {
        deleteStates.run(r.run_id);
        deleteRun.run(r.run_id);
        removed++;
      }
    }
    return removed;
  }

  close() {
    this.db.close();
  }
}
