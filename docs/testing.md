# Testing `secure-review`

Two layers, both verified on this machine (Windows 11, Git Bash + PowerShell 5.1, Python 3.13):

1. **Unit/integration suite** — 84 tests, no real scanners needed (parser tests run against verbatim real-output fixtures).
2. **Real end-to-end** — `scripts/e2e.ps1` builds throwaway vulnerable and clean trees, drives the real console script with real checkov/trivy/bandit, and asserts the full exit-code contract.

---

## 1. The 92-test suite

### Run it

Git Bash:

```bash
.venv/Scripts/python -m pytest -q
```

PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Both forms are safe to run bare: the root `conftest.py` pins a clean,
PID-suffixed basetemp (`%TEMP%\sr-pytest-<pid>`) unless `--basetemp` is
passed explicitly, so the poisoned `pytest-of-jeffr` factory (see quirks
below) is never touched — no more PermissionError at teardown on green
runs.

### One command from anywhere

`run-tests.ps1` at the repo root works from **any** directory — no `cd`, no activation, no policy concerns. It anchors on its own location, uses the venv python when present (falling back to `python` on PATH, the CI layout), gives pytest a PID-suffixed basetemp under `%TEMP%` (the same scheme the root `conftest.py` now applies by default; the script's explicit flag still wins, and it keeps the keep-artifacts-on-red behavior), disables the cache provider so the tree stays pristine, forwards extra arguments verbatim, and exits with pytest's exit code.

```powershell
& "C:\Users\jeffr\jeff's Projects\SecureReview Agent\run-tests.ps1"        # full suite
& "C:\Users\jeffr\jeff's Projects\SecureReview Agent\run-tests.ps1" -k threshold
& "C:\Users\jeffr\jeff's Projects\SecureReview Agent\run-tests.ps1" tests\test_cli.py -x
```

On a green run its scratch dir is removed; on a red one the path is printed and the artifacts kept for inspection.

Both expect: `92 passed` in well under a second. On this machine, if collection dies with `ModuleNotFoundError: No module named 'secure_review'` / `pydantic`, you are on the global Python — the venv was not activated (or activation merged into a previous line). Use the explicit `.venv/Scripts/python` forms above.

### Layout

| File | Count | What it pins |
|---|---|---|
| `tests/test_ai_advisor.py` | 43 | opt-in advisor: inert without `opt_in=True`, field allowlist, safe degradation to `None`, never wired into the CLI |
| `tests/test_cli.py` | 27 | exit contract (0/1/2/3), threshold ranking (`unknown` = worst), missing-scanner exit 1 that never masquerades as a threshold result, `--sarif` emission |
| `tests/test_runner.py` | 13 | parser shapes for all three scanners against **verbatim real-output fixtures** |
| `tests/test_sarif.py` | 5 | SARIF 2.1.0 structure, `properties.severity` verbatim |
| `tests/test_package.py` | 1 | dynamic version + import smoke |
| `tests/test_conftest.py` | 3 | basetemp pin contract: explicit `--basetemp` wins, the default redirects to `sr-pytest-<pid>`, a nested bare session adds no `pytest-of-*` dir |

Subsets:

```bash
.venv/Scripts/python -m pytest tests/test_cli.py -q        # one file
.venv/Scripts/python -m pytest -k threshold -q             # by keyword
```

### Fixtures carry provenance gates

`tests/fixtures/checkov_real.json` and `tests/fixtures/trivy_real.json` are verbatim captures of real scanner output. The tests **assert provenance fields** (`checkov_version == "3.3.20"`, `Trivy.Version == "0.74.0"`, `SchemaVersion == 2`). If a scanner upgrade changes its JSON shape, these tests fail loudly instead of silently losing findings. If you upgrade a scanner, regenerate the fixture from real output and update the provenance gate in the same commit.

### Windows quirks of this machine

- **The apostrophe in the project path** (`C:\Users\jeffr\jeff's Projects\...`) breaks pip's generated `.cmd`/Bash wrapper scripts for anything installed by pip → exit 126, "bad interpreter". This is why:
  - Use `.venv/Scripts/python -m <module>` rather than bare entry points installed by pip, **except** `secure-review.exe` (built by setuptools, works) and `bandit.exe` (works — setuptools exe, not pip cmd).
  - `checkov.cmd` is unusable. Workaround: `python -m checkov.main` — used by the e2e shim below.
- **PowerShell needs `.\` prefix** for relative executables: `.\.venv\Scripts\secure-review.exe scan <path>`.
- **Git Bash mangles `/flags` into paths** when invoking native .exe tools → use `MSYS2_ARG_CONV_EXCL='*'` when invoking `csc.exe` or trivy with `/`-style flags directly.
- **Store stub `python3`** exists but is not the venv; always `python` or the explicit `.venv/Scripts/python`.
- **pytest tmp factory poisoned?** A crashed session left `C:\Users\jeffr\AppData\Local\Temp\pytest-of-jeffr` with damaged ACLs that even admin PowerShell could not remove. Handled at the root since the conftest pin: `conftest.py` sets `%TEMP%\sr-pytest-<pid>` as basetemp unless `--basetemp` is passed explicitly, so bare `pytest` never touches the poisoned tree (`run-tests.ps1` predates this and passes its own flag, which wins).

---

## 2. Real end-to-end: `scripts/e2e.ps1`

### What it proves

Through the **real console script**, on **real vulnerable and clean trees**:

| Probe | Expected |
|---|---|
| `scan <nonexistent> --fail-on none` | exit **2** |
| `scan <file> --fail-on none` | exit **2** |
| `scan <vulnerable> --fail-on high` | exit **3** |
| `scan <vulnerable> --fail-on low` | exit **3** |
| `scan <clean>` (default threshold) | exit **0** |
| `scan <vulnerable>` when a scanner is missing | exit **1** (reduced mode) or **3** (full mode) |
| SARIF emission (full mode) | **SARIF-OK n** — every parsed finding re-serialized through the library and asserted field-by-field (version 2.1.0, driver, ruleId, level, verbatim severity/scanner, message, uri, startLine); then validated against the **official SARIF 2.1.0 schema** (**SCHEMA-OK**) |

It parses findings from all three real scanners (last full run: **24 findings** from checkov 3.3.20, trivy 0.74.0, bandit 1.9.4) and asserts the exact exit codes. It exits 0 iff no probe failed; skips are allowed.

### Capability tiers (why exits 3/0 may skip)

The CLI exits 1 when **any** scanner is missing/failed — tool-error precedence. So exit 3 requires *every* scanner runnable:

- **FULL** — checkov executable, trivy present → all probes run, including exits 3/0/1-as-3.
- **REDUCED** — trivy absent (it is not pip-installable) → exit-3 and exit-0 probes SKIP; the exit-1 probe becomes real (a scanner genuinely missing). Script still exits 0.
- Force reduced mode deterministically with `-SkipShim` — skips the checkov shim build even when csc.exe is available, proving the reduced path on any machine:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\e2e.ps1 -SkipShim
```

The CLI fallback inside the script is CI-friendly: without a repo `.venv` it uses `python -m secure_review.cli` (the package as installed by pip), which is exactly the CI layout.

### How checkov becomes runnable on this box

pip cannot create `checkov.exe` here (apostrophe path), and Windows `CreateProcess` cannot launch `.cmd` files. Detection is sysconfig-first with a `Get-Command` fallback; a `.cmd`-only checkov triggers a **thin C# shim** with `csc.exe` (`%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) that execs `python -m checkov.main`, forwarding args and exit code. It uses a C# **verbatim string** for the embedded python path (a regular literal breaks on `\U` in `C:\Users\...` with CS1009), quotes each forwarded argument, and surfaces csc output when the build fails. This mirrors the manual workaround in `docs/phase4-validation.md`.

### Trivy: provide your own binary

Not pip-installable. The script looks for `%TEMP%\trivy-bin\trivy.exe` by default, or pass `-TrivyDir <dir>`. Pin: **v0.74.0** (the README example pin v0.68.2 does not exist as a release — API 404; and v0.69.x shipped compromised — see `docs/phase3-validation.md`).

```bash
curl -fsSL -o /tmp/trivy.zip \
  https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip
python -c "import zipfile; zipfile.ZipFile(r'C:\Users\jeffr\AppData\Local\Temp\trivy.zip').extractall(r'C:\Users\jeffr\AppData\Local\Temp\trivy-bin')"
```

### Run it

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\e2e.ps1
```

### Expected output (full mode, last verified run)

```
checkov shim built at C:\Users\jeffr\AppData\Local\Temp\sr-e2e-...\bin
e2e target: C:\Users\jeffr\AppData\Local\Temp\sr-e2e-...\target
mode: FULL (checkov runnable: True; trivy present: True)

Probes:
  [ok] exit 2: path does not exist -> exit 2 (expected 2)
  [ok] exit 2 output mentions expected markers
  [ok] exit 2: path is a file, not a directory -> exit 2 (expected 2)
  [ok] exit 2 (file) output mentions expected markers
  [ok] exit 3: --fail-on high on vulnerable tree -> exit 3 (expected 3)
  [ok] exit 3 output mentions expected markers
  (informational) findings parsed: 24
  [ok] exit 3: --fail-on low on vulnerable tree -> exit 3 (expected 3)
  [ok] exit 0: clean tree, default threshold -> exit 0 (expected 0)
  [ok] exit 0 output mentions expected markers
  [ok] exit 3: default threshold, all scanners installed -> exit 3 (expected 3)
  [ok] SARIF 2.1.0 emission matches parsed findings (SARIF-OK 24)
  [ok] SARIF log validates against the official 2.1.0 schema (SCHEMA-OK)

e2e summary: 12 passed, 0 failed, 0 skipped
```

Reduced mode prints `[SKIP]` for the exit-3/exit-0 probes with the reason, and the exit-1 probe becomes the real missing-scanner probe (verified: `6 passed, 0 failed, 1 skipped` with `-SkipShim`). Official-schema validation degrades honestly: `SCHEMA-UNAVAILABLE` (no `jsonschema`, or schemastore unreachable) is a skip, never a false failure; only a real `SCHEMA-FAIL` fails the run. (Verified: FULL mode `12 passed, 0 failed, 0 skipped`, `SARIF-OK 24` + `SCHEMA-OK`.) Note `jsonschema` is not a declared dependency of this package — it arrives transitively via checkov, which is why CI (which installs checkov 3.3.20) validates too; anything else skips the schema check but never fakes it.

### Reference: manual full-mode sweep (what the script automates)

The same contract by hand (Git Bash):

```bash
export PATH="/tmp/checkov-shim:/tmp/trivy-bin:$PWD/.venv/Scripts:$PATH"

# vulnerable tree -> exit 3
.venv/Scripts/secure-review.exe scan /tmp/sr-e2e --fail-on high; echo "exit=$?"   # 3

# clean tree -> exit 0
.venv/Scripts/secure-review.exe scan /tmp/sr-clean; echo "exit=$?"                # 0

# bad path -> exit 2
.venv/Scripts/secure-review.exe scan /nonexistent/path --fail-on none             # 2

# scanner missing -> exit 1 (never masquerades as a threshold result)
```

---

## 3. CI: first real run — what failed and why

`.github/workflows/secure-review.yml` runs two jobs on every PR to `main`, both using the same full-SHA-pinned actions:

- **`scan` (ubuntu-latest)** — installs pinned scanners (checkov 3.3.20, bandit 1.9.4, trivy v0.74.0) and runs `secure-review scan "$GITHUB_WORKSPACE" --fail-on high --sarif "$RUNNER_TEMP/secure-review.sarif"`; JSON + SARIF reports and a Markdown step summary are uploaded as artifacts under `if: always()`, so a red gate still ships its evidence.
- **`e2e-windows` (windows-latest)** — installs `.[test]` + scanners, runs the pytest suite, then `scripts/e2e.ps1` in FULL mode (pip builds a real `checkov.exe` on normal paths; trivy arrives via setup-trivy), proving the exit-code contract and SARIF emission on Windows in CI.

The first real run (2026-09-28, run 36423902300) failed **both** jobs. Three independent defects, none of them scanner-related — postmortem:

### 3.1 The scan job died on a quoted code fence (exit 127)

The "Build Markdown summary" step tried to emit literal markdown fences by quoting them:

```bash
'```'                 # the bug: bash parses a command named ```
printf '```text\n'    # the fix: a literal fence via printf
```

In bash, quotes turn content into a WORD, not into punctuation: `'```'` is a three-backtick **command name**, so the step died with `` ```: command not found`` and exit 127. Quoting-to-escape works for arguments; it never produces literal output. Two lessons: markdown fences inside `run:` blocks must be emitted with `printf`, and a `run:` block this cheap to break deserves a local `bash -n` smoke before it reaches CI.

### 3.2 The e2e job's CLI fallback was a silent no-op

`cli.py` defined `main()` but had no `if __name__ == "__main__":` guard. The e2e script's fallback (no repo `.venv` on CI) runs `python -m secure_review.cli`, which **imports** the module and exits 0 without executing anything. Every probe then measured "exit 0, empty output" and failed on both code and output assertions — the run reported `0 passed, 6 failed` and looked like a scanner problem, but no scanner was ever involved. The fix is the three-line guard (`raise SystemExit(main())`). Lesson: `python -m pkg.module` only behaves as a CLI if the module is *also* runnable as a script; test the fallback path itself, not just the console script.

### 3.3 Why e2e detects checkov via sysconfig, not `Get-Command`

checkov was pip-installed on the runner, yet e2e reported `checkov runnable: False`. Detection used `Get-Command checkov` — a PATH scan — and the setup-python interpreter's script directory is not on the runner PATH in the pwsh step. Worse, even a hit would not have helped: pip's `.cmd` shim is unlaunchable regardless, because Windows `CreateProcess` cannot start `.cmd` files. The fix asks Python itself where it installs scripts — `sysconfig.get_path('scripts')` — and looks for `checkov.exe` there, keeping the PATH lookup only as a fallback. That works identically for a developer venv and a CI install, because both are just "a Python with a scripts directory." Lesson: when another process must launch a tool, resolve it the way that process would — an executable file in a known directory — not via a shell's PATH lookup.

After all three fixes, the full local chain was re-verified before pushing: `run-tests.ps1` → `92 passed`; `scripts\e2e.ps1` → FULL mode `12 passed, 0 failed, 0 skipped` (`SARIF-OK 24` + `SCHEMA-OK`). Then `git push`, `gh pr checks 1 --watch`.

### 3.4 The lint gate (actionlint + shellcheck) — and its verified limit

The workflow now runs a third job, `lint`, before anything burns runner minutes on the scan/e2e matrix. It downloads pinned builds and verifies them:

- **actionlint v1.7.12** — SHA-256 pinned from the release's official `actionlint_1.7.12_checksums.txt`; checks workflow syntax, expressions, action references, and (via its built-in shellcheck integration) every `run:` block.
- **shellcheck v0.11.0** — that release ships no checksum asset, so the pin is the SHA-256 of the official tarball as fetched over TLS when the pin was added (self-attested; the YAML comment says so). Its Windows build reproduces locally what CI checks.

Verified live during adoption: the gate flagged a parse-level problem in a `run:` block immediately (a comment starting with `shellcheck` parses as a shellcheck *directive* — SC1072/SC1073 — never start a comment that way), and `actionlint` exits 0 on the fixed workflow.

**Honest limit, verified by probe:** re-creating the original `'```'` fence in a scratch workflow, actionlint exits **0** — the construct is valid bash that only fails at runtime (exit 127), so no static shellcheck catches it. The gate reliably eliminates the parse-error and classic quoting/expansion classes (SC2086 and friends); the runtime-only class still needs the 3.1 rules: emit fences with `printf`, and smoke-test nontrivial `run:` blocks locally (`bash -n` catches parse errors, a scratch run catches the rest).

Local usage: download the Windows build of actionlint once, then `actionlint -no-color .github/workflows/secure-review.yml` after any workflow edit — it invokes shellcheck from `PATH` automatically when present.
