# Scanner upgrades: the one-commit runbook

Scanner versions are pinned in six places, and they must all move **in the same commit** — a mismatch between the installed scanner and any single pin produces either a false-green (old fixtures parsed by new code) or a red suite that hides the real change. `scripts/upgrade-scanners.ps1` does the mechanical part and refuses to guess the parts that need a human.

## The pins (what has to move together)

| Where | What | Who flips it |
|---|---|---|
| `tests/fixtures/checkov_real.json` | verbatim checkov output (`summary.checkov_version` embeds the version) | script (recapture) |
| `tests/fixtures/trivy_real.json` | verbatim trivy output (`Trivy.Version` embeds the version) | script (recapture) |
| `tests/test_runner.py` | the two provenance asserts (`checkov_version ==`, `Trivy"]["Version"] ==`) | script (regex-located, literal-replaced) |
| `.github/workflows/secure-review.yml` | pip pins `checkov==` / `bandit==` (scan + e2e jobs) | script (literal replace) |
| `.github/workflows/secure-review.yml` | setup-trivy `version: vX.Y.Z` (x2), zip download URL, zip SHA-256 gate | script (hash re-downloaded and re-pinned) |
| docs + code comments | prose claims about scanner behavior ("real 3.3.20 leaves severity None", flag shapes, "24 findings") | **human** — the script only lists them |

The fixture **source tree** is committed at `tests/fixtures/tree/` (`main.tf`: one unencrypted `aws_ebs_volume`, lines 1–4). Without it there is nothing deterministic to recapture from — the original tree was a temp dir that no longer exists, which is exactly how the first recapture attempt failed.

## The flow

```powershell
# 0. Install the new versions FIRST (the script refuses to upgrade anything):
.venv\Scripts\python.exe -m pip install "checkov==<new>" "bandit==<new>"
#    ...and put the new trivy at %TEMP%\trivy-bin\trivy.exe (docs/testing.md §2).

# 1. Run the script:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\upgrade-scanners.ps1 `
    -CheckovVersion <new> -TrivyVersion <new> -BanditVersion <new> -Commit

# 2. Do the printed human checklist (docs counts, stale prose, e2e run).
# 3. Run e2e, push, watch CI:  gh pr checks <N> --watch
```

What the script does, in order:

1. **Preflight** — verifies the *installed* versions in the venv / `%TEMP%\trivy-bin` match the requested versions (it upgrades nothing), and reads the current pins from the provenance asserts. Refuses to run when nothing would change (`-Force` overrides for recapture-only runs).
2. **Capture** — copies `tests/fixtures/tree` to a scratch dir and scans it with the same flags the runner uses (`--output json`, **not** `--compact` — the fixture must be literally what the pinned scanner emits under the runner's argv). A generated Python helper writes the `.new` files as byte-clean UTF-8 (PowerShell 5.1 redirection would write UTF-16+BOM and corrupt them).
3. **Normalize machine noise only** — trivy: `ArtifactName` / `ReportID` / `CreatedAt` → `<capture-dir>`-style markers. checkov: capture paths (including their JSON-escaped forms — plain-text replaces never match backslashed Windows paths inside JSON) and the order-nondeterministic per-check `details` tag list. Everything else stays verbatim; provenance versions inside the captures are real.
4. **Dry parse + rule-set delta** — both captures go through the real `_parse_*` parsers (must yield ≥ 1 finding each) and the rule sets are diffed against the committed fixtures. `CHANGED` is not an error: the script prints exactly which policies appeared/disappeared and lets the suite fail on the stale `by_rule` pins so you update them deliberately.
5. **Flip pins** — provenance asserts, pip lines, setup-trivy versions, zip URL, and the zip SHA-256 (downloaded fresh and pinned from the actual artifact — never hand-computed).
6. **Suite as the gate** — `run-tests.ps1` in a child process (it ends with `exit`). Red suite ⇒ no commit; the usual causes are parser-shape drift or rule-set changes.
7. **Commit (with `-Commit`)** — stages exactly the touched files. Never pushes.

## Why the hash flip is scoped (a war story)

The first cut replaced *every* 64-hex string in the workflow with the new trivy zip hash — which silently rewrote the **actionlint and shellcheck checksums in the lint job** too. Nothing caught it: the suite doesn't read the workflow, and CI would have failed later in lint with a baffling checksum mismatch. The script now extracts the hash only from the e2e step's own `if ($hash -ne '<hash>')` line. Lesson: a global regex over a file you don't fully model is a corruption vector, no matter how sure you are there's "only one" match.

## The human checklist (what the script refuses to guess)

- Rule-set pins in `tests/test_runner.py` (`by_rule` sets) when checkov/trivy policies changed — the suite tells you which.
- Every doc/comment mention of the old versions: they are **empirical claims** ("checkov 3.3.20 leaves item severity `None`", "bandit `-x` takes globs", "arg-order killed `-d`") that must be re-verified against the new scanner before being edited, or honestly retired. The script lists them; it never rewrites them.
- Count claims in `docs/testing.md`: the e2e `SARIF-OK <N>` expectation, "last full run: N findings", and §4's expected numbers — update only after running `scripts/e2e.ps1` against the new scanners and seeing the real count.
- CI behavior differences: run `gh pr checks <N> --watch` and compare the scan job's finding summary with the old run's before merging.

## Verified properties (don't regress these)

- **Idempotent recapture**: two consecutive runs at the same versions produce byte-identical fixture files (sha256-checked). If a recapture diff shows pure reorderings or path churn again, a new noise field appeared — extend the normalization deliberately, never by loosening "verbatim".
- **Guard**: without `-Force`, the script refuses when the pins already match the requested versions.
- **Failure atomicity**: any failure before the promote step leaves the working tree untouched (`.new` files live in scratch); a red suite after promotion leaves changes uncommitted for inspection.

## Live-fire verification log (2026-09-30)

Every path in the script has fired against a real version transition. The wrinkle: on that day **all three pins were already the latest releases** (checkov 3.3.20 uploaded three days prior, trivy v0.74.0, bandit 1.9.4), so the "upgrade" was exercised by simulating an honest past on a throwaway branch: downgrade the venv to checkov 3.3.19, falsify the provenance assert to claim 3.3.19, then let the script drive back to 3.3.20.

What fired, in order — none of it staged or rehearsed:

1. **Preflight refusal.** The first run bounced with `venv checkov is 3.3.19, not 3.3.20 — pip install checkov==3.3.20 first`. The operator (me) had skipped step 0; the script caught it. It upgrades nothing, by contract.
2. **Guard refusal.** A same-versions run without `-Force` was refused (`provenance gates already claim ...; nothing to upgrade`).
3. **The real upgrade run.** Preflight verified the freshly installed 3.3.20, gates claimed 3.3.19, capture ran from the committed tree, delta printed `SAME` (2 + 2 rule sets across 3.3.19 → 3.3.20), the trivy zip hash was re-pinned, and the suite passed 95/95. The recapture reproduced the committed fixture **byte-for-byte** — the canonical normalization survived a real version transition.
4. **The `-Commit` path.** With a stale-fixture world committed first, `-Force -Commit` produced its templated commit staging exactly the one repaired file; the net diff of the whole round trip against `main` was empty.
5. **Empty-commit refusal.** When a repair landed on content identical to HEAD, `-Commit` exited 1 with `nothing to commit - pins and fixtures already match` instead of creating a nothing commit.

Two gotchas worth keeping:

- **"Latest" on PyPI is `info.version`, not the last `releases` entry.** The `releases` object's keys sort lexically, so the naive list-tail read reports `3.3.9` as newer than `3.3.20`. Sort by parsed version, or trust `info.version`.
- **`nothing to commit` is an exit-1 guard, not a crash.** A repair that lands byte-identical to HEAD (e.g. re-running after a falsification was already repaired) is a successful upgrade with no diff; the script says so and stops. Don't read the nonzero exit as a failure to upgrade.

The throwaway branch was deleted after the round trip; `main` was byte-identical before and after, which is itself the strongest statement the recapture normalization makes: an upgrade that changes no behavior changes no bytes.
