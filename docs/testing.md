# Testing `secure-review`

Two layers, both verified on this machine (Windows 11, Git Bash + PowerShell 5.1, Python 3.13):

1. **Unit/integration suite** — 84 tests, no real scanners needed (parser tests run against verbatim real-output fixtures).
2. **Real end-to-end** — `scripts/e2e.ps1` builds throwaway vulnerable and clean trees, drives the real console script with real checkov/trivy/bandit, and asserts the full exit-code contract.

---

## 1. The 84-test suite

### Run it

Git Bash:

```bash
.venv/Scripts/python -m pytest -q
```

PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Both expect: `84 passed in ~0.3s`. On this machine, if collection dies with `ModuleNotFoundError: No module named 'secure_review'` / `pydantic`, you are on the global Python — the venv was not activated (or activation merged into a previous line). Use the explicit `.venv/Scripts/python` forms above.

### Layout

| File | Count | What it pins |
|---|---|---|
| `tests/test_ai_advisor.py` | 43 | opt-in advisor: inert without `opt_in=True`, field allowlist, safe degradation to `None`, never wired into the CLI |
| `tests/test_cli.py` | 22 | exit contract (0/1/2/3), threshold ranking (`unknown` = worst), missing-scanner exit 1 that never masquerades as a threshold result |
| `tests/test_runner.py` | 13 | parser shapes for all three scanners against **verbatim real-output fixtures** |
| `tests/test_sarif.py` | 5 | SARIF 2.1.0 structure, `properties.severity` verbatim |
| `tests/test_package.py` | 1 | dynamic version + import smoke |

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
- **pytest tmp factory poisoned?** A crashed session left `C:\Users\jeffr\AppData\Local\Temp\pytest-of-jeffr` with damaged ACLs that even admin PowerShell could not remove. Sidestep with `--basetemp=.pytest-tmp` (tests don't actually need tmp dirs; the suite is unaffected).

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

It parses findings from all three real scanners (last full run: **24 findings** from checkov 3.3.20, trivy 0.74.0, bandit 1.9.4) and asserts the exact exit codes. It exits 0 iff no probe failed; skips are allowed.

### Capability tiers (why exits 3/0 may skip)

The CLI exits 1 when **any** scanner is missing/failed — tool-error precedence. So exit 3 requires *every* scanner runnable:

- **FULL** — checkov executable, trivy present → all probes run, including exits 3/0/1-as-3.
- **REDUCED** — trivy absent (it is not pip-installable) → exit-3 and exit-0 probes SKIP; the exit-1 probe becomes real (a scanner genuinely missing). Script still exits 0.

### How checkov becomes runnable on this box

pip cannot create `checkov.exe` here (apostrophe path), and Windows `CreateProcess` cannot launch `.cmd` files. The script detects a `.cmd`-only checkov and **builds a thin C# shim** with `csc.exe` (`%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) that execs `python -m checkov.main`, forwarding args and exit code. It uses a C# **verbatim string** for the embedded python path (a regular literal breaks on `\U` in `C:\Users\...` with CS1009), quotes each forwarded argument, and surfaces csc output when the build fails. This mirrors the manual workaround in `docs/phase4-validation.md`.

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

e2e summary: 10 passed, 0 failed, 0 skipped
```

Reduced mode prints `[SKIP]` for the exit-3/exit-0 probes with the reason, and the exit-1 probe becomes the real missing-scanner probe.

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

## 3. CI is the final gate — not yet exercised

`.github/workflows/secure-review.yml` installs pinned scanners (checkov 3.3.20, bandit 1.9.4, trivy v0.74.0) and runs `secure-review scan "$GITHUB_WORKSPACE" --fail-on high` on every PR to `main`. It has **never executed on a real runner** — blocked on `gh auth login` (GitHub.com → HTTPS → browser) in your own terminal. Once you've authenticated, the sequence is: create the private repo → push → PR → `gh run watch` → drive it green → merge.
