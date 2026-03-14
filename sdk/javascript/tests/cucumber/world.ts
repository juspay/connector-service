import { World, setWorldConstructor } from '@cucumber/cucumber';
import * as path from 'path';

const ARTIFACTS_DIR = path.resolve(__dirname, '../../../tests/client_sanity/artifacts');

export class SanityWorld extends World {
  method = '';
  url = '';
  headers: Record<string, string> = {};
  body: string | null = null;
  proxyUrl: string | null = null;
  responseTimeoutMs: number | null = null;

  scenarioId = '';
  sourceId = '';
  judged = false;

  getArtifactsDir() { return ARTIFACTS_DIR; }
  getCaptureFile() { return path.join(ARTIFACTS_DIR, `capture_${this.sourceId}.json`); }
}

setWorldConstructor(SanityWorld);
