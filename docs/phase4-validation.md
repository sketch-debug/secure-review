# Phase 4 validation — optional AI advisor

Validated locally on 2026-09-28 (Windows 11, Git Bash, Python 3.13.15,
`.venv/`). Status labels, per the Phase 3 convention:

- **PASSED (local)** — actually executed this session against the real
  modules; the output shown in the session trace is quoted, and a
  reproduce command is given.
- **NOT CLAIMED** — cannot be true until it runs; do not treat as done.

All tests use mocks. No real AI provider is ever contacted; the
advisor's provider seam (`AdvisorClient`) has no network-capable
implementation in this repository at all.

## 1. Mocked AI responses — PASSED (local)

A mock `AdvisorClient` returned a valid payload; the advisor emitted a
validated `Advisory` and nothing else changed:

```
advisory: finding_id='Bandit/B602/0a1b2c3d4e5f'
          explanation='subprocess with shell=True enables command injection'
          likely_impact='remote code execution via crafted arguments'
          review_focus='replace shell=True with an argument list'
severity in finding (unchanged): HIGH
```

Reproduce: `python -c "from secure_review.ai_advisor import Advisor, AdvisorClient, Advisory; ..."`
(see `tests/test_ai_advisor.py::test_mocked_valid_response_yields_validated_advisory`
for the canonical form). Tests: 79 passing, of which 20 cover the advisor.

## 2. Malformed model output — PASSED (local)

Every invalid shape degraded to `None` — no exception raised into the
caller, finding untouched:

```
empty explanation    -> None
smuggled patch       -> None
non-object           -> None
```

The full battery lives in `tests/test_ai_advisor.py`:
missing/empty/over-length fields, wrong types, whitespace-only fields,
and smuggled keys (`severity`, `suppression`, `patch`, `fixed`,
`confidence`) are each rejected by the schema (`extra="forbid"`).

## 3. AI-disabled mode — PASSED (local)

- Default off **even with a client configured**: `Advisor(client)` →
  `enabled: False`, `advise() -> None`, provider never called
  (`provider called: False` on the mock's request log).
- The scanner works unchanged with AI absent: real console script,
  stub scanners on PATH:

```
-- clean target, default --fail-on none
worst severity: none
fail-on none: below threshold
exit=0

-- findings target, --fail-on high
worst severity: high
fail-on high: threshold met or exceeded
exit=3
```

- Structurally: `cli.py` contains no reference to the advisor
  (`test_scan_cli_is_never_wired_to_the_advisor` asserts this and that
  the scan exit-code contract still holds), and `Advisor`'s public API
  is exactly `advise` and `enabled`.

## 4. Provider errors — PASSED (local)

A client that raises degrades to `None`; the error never propagates:

```
ConnectionError('provider unreachable') -> None
finding after all of it: Finding(scanner='Bandit', rule_id='B602',
    severity='HIGH', message='shell=True', path='...\\run.py', line=14)
```

Covered for `ConnectionError`, `TimeoutError`, and a generic
`RuntimeError` in `test_provider_errors_degrade_to_no_advisory`, each
also asserting the finding is byte-identical afterwards.

## 5. No source code or secrets are sent — PASSED (local)

The allowlisted request contents for a real `Finding`
(`path=C:\Users\jeffr\proj\run.py`, `line=14`):

```
{"message": "shell=True", "rule_id": "B602", "scanner": "Bandit", "severity": "HIGH"}
no secrets/source in request: True
```

Exactly four fields; `path` and `line` are documented exclusions (a
path can embed a username — `jeffr` appears nowhere in the request),
and `finding_id` carries only a short SHA-256 digest of the excluded
location, never the raw path. Pinned by
`test_metadata_never_serializes_source_or_secrets`,
`test_path_and_line_never_reach_the_provider`, and
`test_future_non_allowlisted_finding_field_is_rejected` (a Finding that
grows a new field fails loudly with `TypeError`, it cannot leak).

## 6. Scanner severity and findings remain unchanged — PASSED (local)

The advisor is read-only: no code path mutates a `Finding` (frozen
dataclass; the advisor never receives a setter). Snapshots taken before
each advisor call in the tests — success, degradation, and provider
error paths — all compare equal afterwards, including through a
deliberate smuggled-`patch` payload. The scanner's own severity
vocabulary and `--fail-on` behavior are owned by
`findings.py`/`cli.py`, which the advisor cannot reach (no wiring).

## 7. No fixes are applied — PASSED (local)

Structurally:

- `Advisory` has exactly four text fields
  (`['finding_id', 'explanation', 'likely_impact', 'review_focus']`) —
  no suppression/patch/fix field exists to populate, and
  `extra="forbid"` turns any attempt into `ValidationError`:

```
suppression smuggle rejected: ValidationError
Advisor public API (no apply/fix/suppress): ['advise', 'enabled']
```

- There is no code path from an advisory to scanner results, files, or
  exit codes; advisories are returned to the caller and nothing else.

## 8. No request payloads or credentials are logged — PASSED (local)

The module contains no logging calls. Verified live with a DEBUG-level
root-logger capture spanning the success, degradation, and disabled
paths:

```
log captured (must be empty): ''
```

Pinned by `test_advisor_logs_no_request_payload` (caplog, asserting
both zero records and absence of payload markers: `shell=True`,
`jeffr`, `B602`, `HIGH`, `run.py`).

## 9. Real provider integration — NOT CLAIMED

By design, this repository contains no AI provider client. The
following can only be validated once someone implements
`AdvisorClient` against a real service, and is explicitly out of
scope: network behavior, provider-side data handling, latency/retry
semantics, real-model output quality, and cost. Any real client must
keep the Phase 3 contract: send only `AdvisorRequest.metadata`, never
log payloads, and treat `Advisory` as advisory-only.
