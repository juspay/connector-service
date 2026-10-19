import { test } from "node:test";
import assert from "node:assert/strict";
import { matchingEvents, collectAudit } from "../support/audit.js";

const event = (overrides: Record<string, unknown> = {}) => ({
  request_id: "synthetic-hs-request",
  stage: "ConnectorCall",
  flow_type: "Authorize",
  timestamp: 100,
  request_data: { card_number: "***", api_key: "***" },
  ...overrides,
});
const line = (value: unknown) =>
  JSON.stringify({ ucs_event: JSON.stringify(value) });

test("one HS request retains every flow, repeated connector call, and timestamp tie", () => {
  const events = [
    event({ flow_type: "Authorize", timestamp: 300, stage: "GrpcRequest" }),
    event({ flow_type: "PaymentMethodToken", timestamp: 100 }),
    event({
      flow_type: "PaymentMethodToken",
      timestamp: 100,
      stage: "GrpcRequest",
    }),
    event({ timestamp: 200, url: "https://example.com/first" }),
    event({ timestamp: 250, url: "https://example.com/second" }),
  ];
  assert.deepEqual(
    matchingEvents(events.map(line).join("\n"), "synthetic-hs-request"),
    [events[1], events[2], events[3], events[4], events[0]],
  );
});

test("exact request ID filtering excludes other requests and never scrapes log messages", () => {
  const matching = event();
  const logs = [
    line(event({ request_id: "synthetic-hs-request-other" })),
    JSON.stringify({
      message: `Event JSON: ${JSON.stringify(matching)}`,
      api_key: "private-sentinel",
    }),
    "not JSON",
    JSON.stringify({ ucs_event: "broken JSON" }),
    line(event({ stage: "Unrelated" })),
    line(event({ timestamp: null })),
    line(matching),
  ].join("\n");
  const result = matchingEvents(logs, "synthetic-hs-request");
  assert.deepEqual(result, [matching]);
  assert.ok(!JSON.stringify(result).includes("private-sentinel"));
});

test("API responses without request IDs do not read arbitrary container logs", async () => {
  const result = await collectAudit(undefined, "synthetic-time", async () => {
    assert.fail("No correlation ID, no log read");
  });
  assert.equal(result.status, "unavailable");
  assert.deepEqual(result.events, []);
});

test("buffered structured events receive one bounded retry without duplicating events", async () => {
  let reads = 0;
  const expected = event();
  const result = await collectAudit(
    "synthetic-hs-request",
    "synthetic-time",
    async (since) => {
      assert.equal(since, "synthetic-time");
      return ++reads === 1 ? "" : line(expected);
    },
  );
  assert.equal(reads, 2);
  assert.equal(result.status, "collected");
  assert.deepEqual(result.events, [expected]);
});

test("unavailable evidence never forwards Docker errors or unrelated log contents", async () => {
  const result = await collectAudit(
    "synthetic-hs-request",
    "synthetic-time",
    async () => {
      throw new Error("private-sentinel");
    },
  );
  assert.equal(result.status, "unavailable");
  assert.ok(!JSON.stringify(result).includes("private-sentinel"));
});

test("legacy images produce explicit unavailable evidence, not fabricated events", async () => {
  let reads = 0;
  const result = await collectAudit(
    "synthetic-hs-request",
    "synthetic-time",
    async () => {
      reads++;
      return JSON.stringify({ message: "Event JSON: legacy output" });
    },
  );
  assert.equal(reads, 2);
  assert.equal(result.status, "unavailable");
  assert.deepEqual(result.events, []);
});
