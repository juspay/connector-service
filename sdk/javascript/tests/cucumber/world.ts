import { World, setWorldConstructor } from '@cucumber/cucumber';
import * as path from 'path';

const ARTIFACTS_DIR = path.resolve(__dirname, '../../../tests/client_sanity/artifacts');

export class SanityWorld extends World {
  baseUrl = '';
  method = '';
  url = '';
  headers: Record<string, string> = {};
  queryParams: Array<[string, string]> = [];
  body: string | null = null;
  proxyUrl: string | null = null;
  responseTimeoutMs: number | null = null;

  scenarioId = '';
  sourceId = '';
  judged = false;

  /** Resolve the full URL from base + path + query params. */
  resolveUrl(): string {
    let url = this.url;
    // If the URL is a relative path, prepend the base URL from the Background.
    if (url.startsWith('/')) {
      url = `${this.baseUrl}${url}`;
    }
    if (this.queryParams.length > 0) {
      const qs = this.queryParams.map(([k, v]) => `${k}=${v}`).join('&');
      url += `?${qs}`;
    }
    return url;
  }

  getArtifactsDir() { return ARTIFACTS_DIR; }
  getCaptureFile() { return path.join(ARTIFACTS_DIR, `capture_${this.sourceId}.json`); }
}

setWorldConstructor(SanityWorld);
