import test from "node:test";
import assert from "node:assert/strict";
import { assessReputation } from "../assessment.js";

test("two unavailable sources produce undetermined with explicit reasons", () => {
  const result = assessReputation(
    [{ status: "unavailable", reason: "timeout" }],
    [{ status: "unavailable", reason: "http_error" }]
  );
  assert.equal(result.risk, "undetermined");
  assert.equal(result.urlhausAvailable, false);
  assert.equal(result.threatfoxAvailable, false);
  assert.deepEqual(result.sourceStatus, { urlhaus: "unavailable", threatfox: "unavailable" });
  assert.ok(result.reasons.some(reason => reason.code === "urlhaus_unavailable"));
  assert.ok(result.reasons.some(reason => reason.code === "threatfox_unavailable"));
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

test("two available sources with no match produce no_known_match and a limitation", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "not_listed" }]
  );
  assert.equal(result.risk, "no_known_match");
  assert.equal(result.matchesFound, 0);
  assert.ok(result.reasons.some(reason => reason.code === "no_match_in_available_sources"));
  assert.ok(result.limitations.some(message => message.includes("ne prouve pas")));
});

test("an active URLhaus match is high risk and explains the exact evidence", () => {
  const result = assessReputation(
    [{
      status: "listed",
      checked_host: "bad.example",
      online_url_count: 3,
      url_count: 5,
      first_seen: "2026-08-07"
    }],
    [{ status: "unavailable" }]
  );
  assert.equal(result.risk, "high");
  assert.equal(result.matchesFound, 1);
  const reason = result.reasons.find(item => item.code === "urlhaus_active_malicious_urls");
  assert.equal(reason.evidence.online_url_count, 3);
  assert.equal(reason.indicator, "bad.example");
});

test("a historical URLhaus match is elevated, not high", () => {
  const result = assessReputation(
    [{ status: "listed", checked_host: "old.example", online_url_count: 0, url_count: 2 }],
    [{ status: "not_listed" }]
  );
  assert.equal(result.risk, "elevated");
  assert.ok(result.reasons.some(reason => reason.code === "urlhaus_historical_or_inactive_match"));
});

test("a high-confidence ThreatFox match is high risk with its confidence", () => {
  const result = assessReputation(
    [{ status: "unavailable" }],
    [{ status: "listed", checked_ioc: "bad.example", matches: [{ ioc: "bad.example", confidence_level: 85 }] }]
  );
  assert.equal(result.risk, "high");
  const reason = result.reasons.find(item => item.code === "threatfox_high_confidence_match");
  assert.equal(reason.evidence.confidence_level, 85);
});

test("a low-confidence ThreatFox match is elevated", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "listed", matches: [{ confidence_level: 45 }] }]
  );
  assert.equal(result.risk, "elevated");
  assert.ok(result.reasons.some(reason => reason.code === "threatfox_match_lower_confidence"));
});

test("a ThreatFox match without confidence is not silently treated as high", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "listed", matches: [{ ioc: "unknown.example", confidence_level: null }] }]
  );
  assert.equal(result.risk, "elevated");
});

test("partial provider coverage cannot produce a clean result", () => {
  const result = assessReputation(
    [{ status: "not_listed" }, { status: "unavailable", reason: "timeout" }],
    [{ status: "not_listed" }, { status: "not_listed" }]
  );
  assert.equal(result.risk, "undetermined");
  assert.equal(result.sourceStatus.urlhaus, "partial");
  assert.equal(result.sourceStatus.threatfox, "available");
  assert.match(result.note, /couverture.*incomplète/i);
});

test("null ThreatFox confidence stays unknown rather than becoming zero", () => {
  const result = assessReputation(
    [{ status: "not_listed" }],
    [{ status: "listed", matches: [{ confidence_level: null }] }]
  );
  const reason = result.reasons.find(item => item.code === "threatfox_match_lower_confidence");
  assert.equal(reason.evidence.confidence_level, null);
  assert.match(reason.message, /sans niveau de confiance/);
});
