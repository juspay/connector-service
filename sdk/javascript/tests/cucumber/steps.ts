import { Given, When, Then, Before } from '@cucumber/cucumber';
import { SanityWorld } from './world';
import { execute, createDispatcher } from '../../src/http_client';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const LANG = 'node';
const JUDGE = path.resolve(__dirname, '../../../tests/client_sanity/judge_scenario.js');
const MANIFEST_PATH = path.resolve(__dirname, '../../../tests/client_sanity/manifest.json');

// Build title → id lookup once at import time.
const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
const titleToId: Record<string, string> = {};
for (const s of manifest.scenarios) {
  if (s.title) titleToId[s.title] = s.id;
}

Before(function (this: SanityWorld, { pickle }) {
  if (pickle.tags.some(t => t.name === '@skip_node')) return 'skipped';
  // Resolve scenario ID from the Gherkin scenario title.
  this.scenarioId = titleToId[pickle.name] || '';
  this.sourceId = `${LANG}_${this.scenarioId}`;
});

// ── Given ───────────────────────────────────────────────────────

Given('the echo server is running on port {int}', function (this: SanityWorld, port: number) {
  this.baseUrl = `http://localhost:${port}`;
});

Given('a {string} request to {string}', function (this: SanityWorld, method: string, url: string) {
  this.method = method;
  this.url = url;
});

Given('query parameter {string} is {string}', function (this: SanityWorld, name: string, value: string) {
  this.queryParams.push([name, value]);
});

Given('header {string} is {string}', function (this: SanityWorld, name: string, value: string) {
  this.headers[name] = value;
});

Given('body is {string}', function (this: SanityWorld, body: string) {
  this.body = body.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n');
});

Given('body is:', function (this: SanityWorld, docString: string) {
  // Doc strings use \n; multipart bodies need \r\n line endings and a trailing \r\n.
  const ct = (this.headers['Content-Type'] || '').toLowerCase();
  if (ct.includes('multipart/')) {
    this.body = docString.replace(/\n/g, '\r\n') + '\r\n';
  } else {
    this.body = docString;
  }
});

Given('a response timeout of {int} ms', function (this: SanityWorld, ms: number) {
  this.responseTimeoutMs = ms;
});

Given('the proxy is {string}', function (this: SanityWorld, url: string) {
  this.proxyUrl = url;
});

// ── When (thin: execute + write actual JSON) ────────────────────

When('the request is sent', async function (this: SanityWorld) {
  if (!this.scenarioId) throw new Error('Could not resolve scenario ID from Gherkin title');

  const actualFile = path.join(this.getArtifactsDir(), `actual_${this.sourceId}.json`);
  const captureFile = this.getCaptureFile();
  if (fs.existsSync(captureFile)) fs.unlinkSync(captureFile);
  if (fs.existsSync(actualFile)) fs.unlinkSync(actualFile);

  const fullUrl = this.resolveUrl();

  // Build request
  const request: any = {
    method: this.method,
    url: fullUrl,
    headers: { ...this.headers, 'x-source': this.sourceId, 'x-scenario-id': this.scenarioId },
    body: this.body,
  };
  if (typeof request.body === 'string' && request.body.startsWith('base64:')) {
    request.body = Uint8Array.from(Buffer.from(request.body.replace('base64:', ''), 'base64'));
  }

  const opts: any = {};
  if (this.responseTimeoutMs != null) opts.responseTimeoutMs = this.responseTimeoutMs;

  const dispatcherConfig: any = { ...opts };
  if (this.proxyUrl) dispatcherConfig.proxy = { httpUrl: this.proxyUrl };

  let dispatcher: any;
  try {
    dispatcher = createDispatcher(dispatcherConfig);
  } catch (e: any) {
    const code = e?.errorCode ?? (typeof e?.code === 'string' ? e.code : 'UNKNOWN_ERROR');
    fs.writeFileSync(actualFile, JSON.stringify({ error: { code, message: e?.message || String(e) } }, null, 2));
    return;
  }

  let output: any = {};
  try {
    const resp = await execute(request, opts, dispatcher);
    const ct = (resp.headers['content-type'] || '').toLowerCase();
    const bodyStr = ct.includes('application/octet-stream')
      ? Buffer.from(resp.body).toString('base64')
      : new TextDecoder().decode(resp.body);
    output.response = { statusCode: resp.statusCode, headers: resp.headers, body: bodyStr };
  } catch (e: any) {
    const code = e?.errorCode ?? (typeof e?.code === 'string' ? e.code : 'UNKNOWN_ERROR');
    output.error = { code, message: e?.message || String(e) };
  }

  fs.writeFileSync(actualFile, JSON.stringify(output, null, 2));
  await new Promise(r => setTimeout(r, 200)); // wait for echo server capture
});

// ── Then (delegate ALL assertions to the shared judge) ──────────

Then('the response status should be {int}', function () { /* validated by judge */ });
Then('the response body should be {string}', function () { /* validated by judge */ });
Then('the response header {string} should be {string}', function () { /* validated by judge */ });
Then('the response should have multi-value header {string} with values {string}', function () { /* validated by judge */ });

Then('the SDK should return error {string}', function (this: SanityWorld) {
  runJudge(this);
});

Then('the server should have received the correct request', function (this: SanityWorld) {
  runJudge(this);
});

function runJudge(world: SanityWorld) {
  if (world.judged) return; // only run once per scenario
  world.judged = true;
  try {
    execFileSync('node', [JUDGE, LANG, world.scenarioId], { stdio: ['pipe', 'pipe', 'inherit'] });
  } catch (e: any) {
    const stdout = e.stdout?.toString() || '';
    let msg = `Judge FAILED for ${world.scenarioId}`;
    try { msg = JSON.parse(stdout).message; } catch {}
    throw new Error(msg);
  }
}
