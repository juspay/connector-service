import { World, setWorldConstructor } from '@cucumber/cucumber';
import * as path from 'path';
import * as fs from 'fs';

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

  response: { statusCode: number; headers: Record<string, string>; body: string } | null = null;
  error: { code: string; message: string } | null = null;

  getArtifactsDir() {
    return ARTIFACTS_DIR;
  }

  getCaptureFile() {
    return path.join(ARTIFACTS_DIR, `capture_${this.sourceId}.json`);
  }

  readCapture(): any | null {
    const file = this.getCaptureFile();
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  }
}

setWorldConstructor(SanityWorld);
