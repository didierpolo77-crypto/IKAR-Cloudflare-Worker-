# IKAR threat-intelligence provider contract

This document describes the extension point for future reputation providers. It does not mean those providers are currently connected.

## Current providers

- URLhaus (abuse.ch): host/domain and resolved-IP lookups.
- ThreatFox (abuse.ch): exact IOC lookups.
- AdGuard Public DNS: DNS resolution only; DNS resolution is not a reputation verdict.

## Normalized result contract

Each provider adapter should return one result per checked indicator:

- `provider`: human-readable provider name.
- `status`: `listed`, `not_listed`, or `unavailable`.
- `checked_indicator`: the exact domain/IP/URL/hash queried.
- `reason`: stable machine-readable failure code when unavailable.
- `evidence`: provider-specific evidence, including timestamps and confidence when supplied by the provider.

Rules:

1. A timeout, HTTP error, invalid response, quota limit, or missing credential is `unavailable`, never `not_listed`.
2. Preserve the provider's original confidence and timestamps; do not invent them.
3. Keep provider-specific evidence in its own result object.
4. Risk policy must be explicit and tested before a provider can influence the final risk.
5. Do not add raw URLs or sensitive query data to logs.
6. A no-match result is not proof of safety.

## Candidate integrations (not active)

- Google Safe Browsing: domain/URL threat matches. Define URL canonicalization and threat-type mapping before use.
- VirusTotal: domain, IP, and URL reports. Normalize malicious/suspicious/harmless/undetected counts carefully; do not equate undetected with harmless.
- Additional IP/domain reputation feeds: document coverage, update frequency, licensing, rate limits, confidence semantics, and failure behavior before integration.

## Risk policy currently implemented

- `high`: URLhaus reports one or more URLs still online, or ThreatFox reports a match with confidence >= 70/100.
- `historical`: URLhaus retains an entry with no URL currently confirmed online, ThreatFox has no match, and both sources fully answered. This is historical evidence, not an active-threat verdict.
- `elevated`: a ThreatFox match below the high-risk confidence threshold, or a URLhaus match combined with other risk evidence or incomplete source coverage.
- `no_known_match`: both current sources answered successfully and neither returned a match.
- `undetermined`: source coverage is insufficient or sources are unavailable.

The API's `assessment.reasons`, `source_status`, `decision_criteria`, and `limitations` fields expose the basis and limits of the current decision.
