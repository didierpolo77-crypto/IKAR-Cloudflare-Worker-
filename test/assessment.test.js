import test from "node:test";
import assert from "node:assert/strict";
import { assessReputation } from "../assessment.js";

test("two unavailable sources produce undetermined", () => {
  const result = assessReputation(
    [{ status: "unavailable" }],
    [{ status: "unavailable" }]
  );
  assert.equal(result.risk, "undetermined");
  assert.equal(result.urlhausAvailable, false);
  assert.equal(result.threatfoxAvailable, false);
  assert.match(result.note, /pas fourni assez de données/);
});

test("one available source with no match remains undetermined", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "unavailable" }]
  );
  assert.equal(result.risk, "undetermined");
  assert.equal(result.urlhausAvailable, true);
  assert.equal(result.threatfoxAvailable, false);
});

test("two available sources with no match produce no_known_match", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "not_listed" }]
  );
  assert.equal(result.risk, "no_known_match");
  assert.equal(result.matchesFound, 0);
});

test("an active URLhaus match remains high risk", () => {
  const result = assessReputation(
    [{ status: "listed", online_url_count: 1 }],
    [{ status: "unavailable" }]
  );
  assert.equal(result.risk, "high");
  assert.equal(result.matchesFound, 1);
});

test("a high-confidence ThreatFox match remains high risk", () => {
  const result = assessReputation(
    [{ status: "unavailable" }],
    [{ status: "listed", matches: [{ confidence_level: 85 }] }]
  );
  assert.equal(result.risk, "high");
});
