#!/usr/bin/env node
/**
 * Per-scenario judge CLI — reuses the same normalization and assertion logic
 * as judge.js but for a single (lang, scenario_id) pair.
 *
 * Usage:  node judge_scenario.js <lang> <scenario_id>
 * Exit 0 = PASS, exit 1 = FAIL/MISSING.
 * Stdout is a JSON object: { status, message, diff? }
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const CLIENT_SANITY_DIR = __dirname;
const ARTIFACTS_DIR = path.join(CLIENT_SANITY_DIR, 'artifacts');
const MANIFEST_PATH = path.join(CLIENT_SANITY_DIR, 'manifest.json');

// ── Normalization helpers (identical to judge.js) ──────────────

const IGNORED_HEADERS = [
  'user-agent', 'host', 'connection', 'accept-encoding',
  'content-length', 'x-source', 'x-scenario-id', 'accept-language',
  'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-dest', 'priority',
  'accept', 'keep-alive', 'date', 'transfer-encoding',
];

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    const lk = key.toLowerCase();
    if (!IGNORED_HEADERS.includes(lk)) normalized[lk] = value;
  }
  return normalized;
}

function normalizeUrl(urlStr) {
  try { return new URL(urlStr).href; } catch { return urlStr; }
}

function normalizeResponseHeaders(headers) {
  const n = normalizeHeaders(headers);
  if (n['set-cookie'] !== undefined) {
    const v = n['set-cookie'];
    const arr = Array.isArray(v) ? [...v] : (v != null && v !== '' ? [String(v)] : []);
    n['set-cookie'] = arr.flatMap(s => String(s).split(/\s*,\s*/).filter(Boolean)).sort();
  }
  return n;
}

function normalizeBody(body, headers) {
  const ct = Object.entries(headers).find(([k]) => k.toLowerCase() === 'content-type')?.[1] || '';
  if (ct.includes('multipart/form-data')) {
    const m = ct.match(/boundary=([^;]+)/);
    if (m) {
      const re = new RegExp(m[1].replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g');
      return body.replace(re, 'REFERENCE_BOUNDARY');
    }
  }
  return body;
}

// ── Core verification (same logic as judge.js verifyScenario) ──

function verifyScenario(lang, scenarioId, expectedError) {
  const goldenPath  = path.join(ARTIFACTS_DIR, `golden_${scenarioId}.json`);
  const actualPath  = path.join(ARTIFACTS_DIR, `actual_${lang}_${scenarioId}.json`);
  const capturePath = path.join(ARTIFACTS_DIR, `capture_${lang}_${scenarioId}.json`);

  if (expectedError) {
    if (!fs.existsSync(actualPath)) return { status: 'MISSING', message: 'Actual error capture missing' };
    const actual = JSON.parse(fs.readFileSync(actualPath, 'utf8'));
    const code = actual?.error?.code;
    if (!code) return { status: 'FAILED', message: 'Actual error.code missing' };
    try {
      assert.strictEqual(String(code), String(expectedError), 'Error Code Mismatch');
      return { status: 'SUCCESS', message: 'Expected error code matched' };
    } catch (e) {
      return { status: 'FAILED', message: e.message, diff: { actual: e.actual, expected: e.expected } };
    }
  }

  if (!fs.existsSync(goldenPath))  return { status: 'MISSING', message: 'Golden capture missing' };
  if (!fs.existsSync(actualPath))  return { status: 'MISSING', message: 'Actual capture missing' };
  if (!fs.existsSync(capturePath)) return { status: 'MISSING', message: 'Echo server capture missing' };

  const golden  = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
  const actual  = JSON.parse(fs.readFileSync(actualPath, 'utf8'));
  const capture = JSON.parse(fs.readFileSync(capturePath, 'utf8'));

  try {
    // Speaker: request parity
    assert.strictEqual(capture.method, golden.method, 'Method Mismatch');
    assert.strictEqual(normalizeUrl(capture.url), normalizeUrl(golden.url), 'URL Mismatch');
    assert.deepStrictEqual(normalizeHeaders(capture.headers), normalizeHeaders(golden.headers), 'Headers Mismatch');
    assert.strictEqual(normalizeBody(capture.body, capture.headers), normalizeBody(golden.body, golden.headers), 'Body Content Mismatch');

    // Listener: response parity
    if (golden.response && actual.response) {
      assert.strictEqual(actual.response.statusCode, golden.response.statusCode, 'Response Status Mismatch');
      assert.deepStrictEqual(
        normalizeResponseHeaders(actual.response.headers || {}),
        normalizeResponseHeaders(golden.response.headers || {}),
        'Response Headers Mismatch',
      );
      assert.strictEqual(
        actual.response.body != null ? String(actual.response.body) : '',
        golden.response.body != null ? String(golden.response.body) : '',
        'Response Body Mismatch',
      );
    }

    return { status: 'SUCCESS', message: 'Perfect Parity' };
  } catch (e) {
    return { status: 'FAILED', message: e.message, diff: { actual: e.actual, expected: e.expected } };
  }
}

// ── CLI entry ──────────────────────────────────────────────────

const [lang, scenarioId] = process.argv.slice(2);
if (!lang || !scenarioId) {
  console.error('Usage: node judge_scenario.js <lang> <scenario_id>');
  process.exit(2);
}

const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
const scenario = manifest.scenarios.find(s => s.id === scenarioId);
if (!scenario) {
  console.log(JSON.stringify({ status: 'MISSING', message: `Unknown scenario: ${scenarioId}` }));
  process.exit(1);
}

const result = verifyScenario(lang, scenarioId, scenario.expected_error || null);
console.log(JSON.stringify(result));
process.exit(result.status === 'SUCCESS' ? 0 : 1);
