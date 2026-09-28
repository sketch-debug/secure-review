# Phase 3 validation — GitHub Actions integration

Validated locally on 2026-09-28 (Windows 11, Git Bash, Python 3.13.15, venv at
`.venv/`). Every item below is labeled honestly:

- **PASSED (local)** — actually executed on this machine; commands included so
  you can re-run them.
- **REQUIRES GITHUB** — can only pass once the repo is pushed and a pull
  request exists. Steps are written out; none are claimed as passed.
- **NOT CLAIMED** — explicitly not verified; do not trust it as done.

## 1. Workflow permissions and secrets exposure — PASSED (local)

Parsed `.github/workflows/secure-review.yml` with PyYAML and asserted:

- top-level `permissions: {}`; job-level `permissions: {contents: read}`;
  nothing else is granted.
- `persist-credentials: false` on checkout.
- zero `secrets.*` references anywhere in the file (grep + parse).
- trigger is `pull_request` → `branches: [main]` (never
  `pull_request_target`), so PR code gets a read-only token and no secrets.

```
python -c "import yaml; d=yaml.safe_load(open('.github/workflows/secure-review.yml')); print(d['permissions'], d['jobs']['scan']['permissions'])"
```

REQUIRES GITHUB: confirm in the run's UI that the token annotation reads
`contents: read` for the job.

## 2. Third-party action SHA pinning — PASSED (local)

All four `uses:` entries are full 40-hex SHAs, each resolved through the
GitHub API from its GPG-verified release tag, with the release named in a
trailing comment:

| Action | Release |
|---|---|
| `actions/checkout` | v7.0.1 |
| `actions/setup-python` | v7.0.0 |
| `aquasecurity/setup-trivy` | v0.3.1 (README-documented SHA) |
| `actions/upload-artifact` | v7.0.1 |

The Trivy **binary** is separately pinned to `v0.74.0` — chosen because the
March 2026 trivy-action compromise shipped via a malicious `v0.69.4` release,
and because an earlier README-example pin (`v0.68.2`) turned out not to exist
as a release; v0.74.0 is the version the config-mode JSON parser was
empirically validated against.

REQUIRES GITHUB: Dependabot alerts or a pinning bot may flag the setup-trivy
SHA as newer releases land; re-verify the SHA still points at v0.3.1.

## 3a. Vulnerable PR produces findings — PASSED (local)

Executed against the real console script with stub scanners on PATH
(Checkov/Trivy stubs exit 0; bandit stub emits real bandit-shaped JSON with a
B602 HIGH finding) plus real bandit on the same directory:

```
- Bandit: finding B602 (HIGH) bad.py:3
worst severity: high
fail-on high: threshold met or exceeded
exit=3
```

## 3b. Clean PR produces no findings — PASSED (local)

Same setup, no findings in scanner output:

```
worst severity: none
fail-on high: below threshold
exit=0
```

REQUIRES GITHUB: repeat both scenarios as real PRs against the repo and
confirm the check conclusion is `failure` (3a) and `success` (3b).

## 4. `--fail-on` behavior — PASSED (local)

- Exit-code contract (from `secure-review scan --help` and the parser
  epilog): 0 = below threshold, 1 = scanner execution problem, 2 = invalid
  path, 3 = threshold met or exceeded.
- Default is `none`: any finding at all exits 3 (test:
  `test_default_fail_on_is_none`).
- Every threshold exercised: `none/low/medium/high/critical` against findings
  of LOW/MEDIUM/HIGH/CRITICAL/unknown severity (36 tests pass; see
  `tests/test_cli.py`).
- Unknown severity values (e.g. `BANANA`) fail **every** threshold — they are
  never silently passed over (`test_unknown_severity_fails_every_threshold`).
- Unknown `--fail-on` values are rejected by argparse with exit 2.
- Live: `--fail-on high` on a HIGH finding → 3; `--fail-on critical` on HIGH
  → 0; clean scan → 0 under all thresholds.

## 5. Artifact upload (JSON, Markdown, SARIF) — PASSED (local)

The three artifacts the workflow uploads were generated from real outputs and
then re-opened and inspected:

- `bandit.json` — real `bandit -f json` run; parses, 3 results.
- `summary.md` — real scan summary wrapped in a fenced block; opens.
- `secure-review.sarif` — findings extracted by the runner from a real scan
  run, rendered by `secure_review.sarif.to_json`, and **validated against the
  official SARIF 2.1.0 schema** (json.schemastore.org); opens, 1 result.

REQUIRES GITHUB: run the workflow on a PR, download the
`secure-review-reports-<N>` artifact from the run page, unzip it, and open
each file; also confirm the Markdown job summary renders on the run page.

## 6. Scanner failures and missing tools — PASSED (local)

- All scanner binaries removed from PATH →
  `scan failure: a scanner was missing, timed out, or failed to run`, exit **1**.
- Missing scanners with findings present and `--fail-on none` → still exit 1,
  never a threshold result (requirement: a scan failure is never reported as
  a threshold result).
- Scanner success with unparseable JSON → tool failure + explicit
  `secure-review/missing-parse-output` finding (test-pinned).
- Timeout → `timeout` status, proven live earlier with 60 s sleeper stubs
  against a 1 s parameter limit.

## 7. Workflow execution — REQUIRES GITHUB, NOT CLAIMED

The workflow has never run. To validate for real:

1. Push the repo to GitHub.
2. Open a PR containing a deliberate finding (e.g. `subprocess.call(..., shell=True)`).
3. Confirm: check runs, exits 3, conclusion `failure`, artifacts downloadable,
   summary visible.
4. Open a clean PR; confirm exit 0, conclusion `success`, artifacts present.
5. Temporarily break a pin (tag instead of SHA) and confirm your review
   process catches it.

## Known gaps found during validation (fixed)

- `run:` steps originally lacked explicit `shell: bash`; added so
  `set -o pipefail` semantics hold for the `tee`-piped scan step.
- SARIF `region` was initially nested inside `artifactLocation`; the official
  schema rejected it — now a sibling under `physicalLocation`.
- Scanner argument prefixes (`checkov -d`, `trivy config`, `bandit -r`) were
  added after discovering bare-invocation would fail against real binaries.
