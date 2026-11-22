import test from "node:test";
import assert from "node:assert/strict";
import { lookupUrlhausHost, lookupThreatFoxIoc } from "../reputation.js";

function response(status, body, jsonError = false) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      if (jsonError) throw new Error("invalid json");
      return body;
    }
  };
}

test("URLhaus reports unavailable when the network request fails", async () => {
  const result = await lookupUrlhausHost("example.com", async () => {
    throw new Error("simulated network outage");
  }, "test-key");
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "urlhaus_connection_failed");
});

test("URLhaus reports unavailable on HTTP errors", async () => {
  const result = await lookupUrlhausHost("example.com", async () => response(503, {}), "test-key");
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "urlhaus_http_error");
});

test("URLhaus reports unavailable on malformed upstream JSON", async () => {
  const result = await lookupUrlhausHost("example.com", async () => response(200, null, true), "test-key");
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "urlhaus_invalid_response");
});

test("URLhaus distinguishes a successful no-match response", async () => {
  const result = await lookupUrlhausHost("example.com", async () => response(200, { query_status: "no_results" }), "test-key");
  assert.equal(result.status, "not_listed");
});

test("ThreatFox reports unavailable when the network request fails", async () => {
  const result = await lookupThreatFoxIoc("example.com", "test-key", async () => {
    throw new Error("simulated network outage");
  });
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "threatfox_connection_failed");
});

test("ThreatFox reports unavailable on HTTP errors", async () => {
  const result = await lookupThreatFoxIoc("example.com", "test-key", async () => response(503, {}));
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "threatfox_http_error");
});

test("ThreatFox reports unavailable on malformed upstream JSON", async () => {
  const result = await lookupThreatFoxIoc("example.com", "test-key", async () => response(200, null, true));
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "threatfox_invalid_response");
});

test("ThreatFox distinguishes a successful no-match response", async () => {
  const result = await lookupThreatFoxIoc("example.com", "test-key", async () => response(200, { query_status: "no_result" }));
  assert.equal(result.status, "not_listed");
});
