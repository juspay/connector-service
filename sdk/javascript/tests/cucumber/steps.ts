import { Given, When, Then, Before } from '@cucumber/cucumber';
import { SanityWorld } from './world';
import { execute, createDispatcher } from '../../src/http_client';
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';

const LANG = 'node';

// Tags that indicate this language should skip the scenario
const SKIP_TAGS = ['@skip_node'];

Before(function (this: SanityWorld, { pickle }) {
  const tags = pickle.tags.map(t => t.name);
  if (tags.some(t => SKIP_TAGS.includes(t))) {
    return 'skipped';
  }
});

Given('the echo server is running on port {int}', function (this: SanityWorld, _port: number) {
  // Echo server is started externally before test run; this is a documentation step.
});

Given('a {string} request to {string}', function (this: SanityWorld, method: string, url: string) {
  this.method = method;
  this.url = url;
});

Given('header {string} is {string}', function (this: SanityWorld, name: string, value: string) {
  this.headers[name] = value;
});

Given('body is {string}', function (this: SanityWorld, body: string) {
  // Handle escaped sequences from Gherkin
  this.body = body.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n');
});

Given('a response timeout of {int} ms', function (this: SanityWorld, ms: number) {
  this.responseTimeoutMs = ms;
});

Given('the proxy is {string}', function (this: SanityWorld, url: string) {
  this.proxyUrl = url;
});

When('the request is sent as scenario {string}', async function (this: SanityWorld, scenarioId: string) {
  this.scenarioId = scenarioId;
  this.sourceId = `${LANG}_${scenarioId}`;

  // Clean old artifacts
  const captureFile = this.getCaptureFile();
  const actualFile = path.join(this.getArtifactsDir(), `actual_${this.sourceId}.json`);
  if (fs.existsSync(captureFile)) fs.unlinkSync(captureFile);
  if (fs.existsSync(actualFile)) fs.unlinkSync(actualFile);

  // Build request
  const request: any = {
    method: this.method,
    url: this.url,
    headers: {
      ...this.headers,
      'x-source': this.sourceId,
      'x-scenario-id': this.scenarioId,
    },
    body: this.body,
  };

  // Handle base64 body
  if (typeof request.body === 'string' && request.body.startsWith('base64:')) {
    request.body = Uint8Array.from(Buffer.from(request.body.replace('base64:', ''), 'base64'));
  }

  // Build options
  const opts: any = {};
  if (this.responseTimeoutMs != null) {
    opts.responseTimeoutMs = this.responseTimeoutMs;
  }

  // Build dispatcher with proxy support
  const dispatcherConfig: any = { ...opts };
  if (this.proxyUrl) {
    dispatcherConfig.proxy = { httpUrl: this.proxyUrl };
  }

  let dispatcher: any;
  try {
    dispatcher = createDispatcher(dispatcherConfig);
  } catch (e: any) {
    const code = e?.errorCode ?? (typeof e?.code === 'string' ? e.code : 'UNKNOWN_ERROR');
    this.error = { code, message: e?.message || String(e) };
    return;
  }

  try {
    const sdkResponse = await execute(request, opts, dispatcher);
    const ct = (sdkResponse.headers['content-type'] || '').toLowerCase();
    const bodyStr = ct.includes('application/octet-stream')
      ? Buffer.from(sdkResponse.body).toString('base64')
      : new TextDecoder().decode(sdkResponse.body);

    this.response = {
      statusCode: sdkResponse.statusCode,
      headers: sdkResponse.headers,
      body: bodyStr,
    };
  } catch (e: any) {
    const code = e?.errorCode ?? (typeof e?.code === 'string' ? e.code : 'UNKNOWN_ERROR');
    this.error = { code, message: e?.message || String(e) };
  }

  // Wait briefly for echo server to write capture file
  await new Promise(r => setTimeout(r, 200));
});

Then('the response status should be {int}', function (this: SanityWorld, expectedStatus: number) {
  assert.ok(this.response, `Expected a response but got error: ${JSON.stringify(this.error)}`);
  assert.strictEqual(this.response!.statusCode, expectedStatus,
    `Status mismatch: expected ${expectedStatus}, got ${this.response!.statusCode}`);
});

Then('the response body should be {string}', function (this: SanityWorld, expectedBody: string) {
  assert.ok(this.response, `Expected a response but got error: ${JSON.stringify(this.error)}`);
  assert.strictEqual(this.response!.body, expectedBody,
    `Body mismatch: expected ${expectedBody}, got ${this.response!.body}`);
});

Then('the response header {string} should be {string}', function (this: SanityWorld, name: string, value: string) {
  assert.ok(this.response, `Expected a response but got error: ${JSON.stringify(this.error)}`);
  const actual = this.response!.headers[name.toLowerCase()];
  assert.strictEqual(actual, value, `Header "${name}" mismatch: expected "${value}", got "${actual}"`);
});

Then('the response should have multi-value header {string} with values {string}', function (this: SanityWorld, name: string, valuesStr: string) {
  assert.ok(this.response, `Expected a response but got error: ${JSON.stringify(this.error)}`);
  const expectedValues = valuesStr.split(',').sort();
  const actual = this.response!.headers[name.toLowerCase()];
  const actualValues = (Array.isArray(actual) ? actual : (actual || '').split(/\s*,\s*/)).sort();
  assert.deepStrictEqual(actualValues, expectedValues,
    `Multi-value header "${name}" mismatch`);
});

Then('the SDK should return error {string}', function (this: SanityWorld, expectedCode: string) {
  assert.ok(this.error, `Expected error "${expectedCode}" but got response: ${JSON.stringify(this.response)}`);
  assert.strictEqual(this.error!.code, expectedCode,
    `Error code mismatch: expected "${expectedCode}", got "${this.error!.code}"`);
});

Then('the server should have received the correct request', function (this: SanityWorld) {
  const capture = this.readCapture();
  assert.ok(capture, `Echo server capture file not found for ${this.sourceId}`);

  // Verify method
  assert.strictEqual(capture.method, this.method, 'Captured method mismatch');

  // Verify URL (normalize for encoding differences)
  const normalizeUrl = (u: string) => { try { return new URL(u).href; } catch { return u; } };
  assert.strictEqual(normalizeUrl(capture.url), normalizeUrl(this.url), 'Captured URL mismatch');

  // Verify headers (ignoring transport noise)
  const IGNORED = ['user-agent', 'host', 'connection', 'accept-encoding', 'content-length',
    'x-source', 'x-scenario-id', 'accept', 'keep-alive', 'date', 'transfer-encoding',
    'accept-language', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-dest', 'priority'];

  const expectedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(this.headers)) {
    if (!IGNORED.includes(k.toLowerCase())) expectedHeaders[k.toLowerCase()] = v;
  }
  const capturedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(capture.headers)) {
    if (!IGNORED.includes(k.toLowerCase())) capturedHeaders[k.toLowerCase()] = String(v);
  }
  assert.deepStrictEqual(capturedHeaders, expectedHeaders, 'Captured headers mismatch');

  // Verify body (with multipart boundary normalization)
  const expectedBody = this.body ? this.body.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n') : '';
  const capturedBody = capture.body || '';
  const normalizeMultipart = (body: string, headers: Record<string, string>) => {
    const ct = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-type')?.[1] || '';
    if (ct.includes('multipart/form-data')) {
      const m = ct.match(/boundary=([^;]+)/);
      if (m) return body.replace(new RegExp(m[1].replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g'), 'REFERENCE');
    }
    return body;
  };
  assert.strictEqual(
    normalizeMultipart(capturedBody, capture.headers),
    normalizeMultipart(expectedBody, this.headers),
    'Captured body mismatch'
  );
});
