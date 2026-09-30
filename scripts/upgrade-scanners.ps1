# Scanner-upgrade runbook (companion doc: docs/scanner-upgrades.md).
#
# The fixture SOURCE tree is committed at tests/fixtures/tree so a recapture
# reproduces the same findings years later (plain `resource "aws_ebs_volume"`
# block, lines 1-4: CKV_AWS_3/189 fail, CKV2_AWS_2 passes; trivy AWS-0026/27
# at startline 1). The original temp capture tree was never committed; this
# one was reconstructed to match the committed fixtures and the next capture
# is made from it. NOTE the file is committed as main.tf.FIXTURE, not
# main.tf: scanners trigger on the .tf extension, and this repo's own CI
# scan gate (secure-review scan . --fail-on high) must not see the fixture's
# deliberately-vulnerable HIGH finding as a real repo finding. The script
# renames it back to main.tf in its scratch copy before capturing.
#
# Recaptures tests/fixtures/checkov_real.json and trivy_real.json from the
# committed fixture tree (tests/fixtures/tree) using the scanners installed
# in the repo venv, flips the machine-verified version pins (provenance
# asserts + workflow), runs the suite, and with -Commit stages exactly the
# files it touched into one commit. It never pushes.
#
# What it deliberately does NOT do:
#   - it does not upgrade anything (pip install / trivy download are the
#     human's job, done BEFORE running this script);
#   - it does not rewrite prose claims about scanner behavior ("real 3.3.20
#     leaves severity None" and friends) - it lists them for hand review,
#     because a comment must never assert something nobody re-verified;
#   - it does not touch rule-set pins in tests when policies change; the
#     suite fails on those on purpose and the delta is printed.
#
# Implementation notes (why it looks like this):
#   - captures go through a generated Python helper, not PowerShell
#     redirection: PS 5.1 redirection writes UTF-16 with a BOM, which would
#     corrupt the byte-for-byte JSON fixtures;
#   - helper scripts are generated into a scratch dir and passed as plain
#     argv - no inline python -c quoting on this apostrophe-path machine;
#   - run-tests.ps1 is invoked as a child powershell.exe because it ends
#     with `exit $code`, which would end this script too if dot-sourced.

[CmdletBinding()]
param(
    # Bare versions, e.g. -CheckovVersion 3.4.0 -TrivyVersion 0.75.1 -BanditVersion 1.9.5
    [Parameter(Mandatory)] [ValidatePattern('^\d+\.\d+(\.\d+)?$')] [string]$CheckovVersion,
    [Parameter(Mandatory)] [ValidatePattern('^\d+\.\d+(\.\d+)?$')] [string]$TrivyVersion,
    [Parameter(Mandatory)] [ValidatePattern('^\d+\.\d+(\.\d+)?$')] [string]$BanditVersion,
    [string]$TrivyDir = (Join-Path $env:TEMP 'trivy-bin'),   # where trivy.exe lives locally
    [switch]$Force,                                          # allow recapture when versions are unchanged
    [switch]$Commit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python      = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$TreeDir     = Join-Path $ProjectRoot 'tests\fixtures\tree'
$Fixtures    = @{
    checkov = Join-Path $ProjectRoot 'tests\fixtures\checkov_real.json'
    trivy   = Join-Path $ProjectRoot 'tests\fixtures\trivy_real.json'
}
$TestFile    = Join-Path $ProjectRoot 'tests\test_runner.py'
$RunnerFile  = Join-Path $ProjectRoot 'src\secure_review\runner.py'
$Workflow    = Join-Path $ProjectRoot '.github\workflows\secure-review.yml'

function Fail([string]$msg) { throw "upgrade-scanners: $msg" }
function Step([string]$msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }

foreach ($f in @($Python, $TreeDir, $Fixtures.checkov, $Fixtures.trivy, $TestFile, $Workflow)) {
    if (-not (Test-Path -LiteralPath $f)) { Fail "required path missing: $f" }
}
$TrivyExe = Join-Path $TrivyDir 'trivy.exe'
if (-not (Test-Path -LiteralPath $TrivyExe)) {
    Fail "trivy.exe not found at $TrivyExe (pass -TrivyDir or install it, see docs/testing.md section 2)"
}

# ---------------------------------------------------------------- preflight
Step 'Preflight: installed scanner versions'
$checkovInstalled = (& $Python -m checkov.main --version 2>$null | Select-Object -First 1).Trim()
if (-not $checkovInstalled) { Fail 'python -m checkov.main --version produced nothing (apostrophe-path quirk: never use checkov.cmd directly)' }
$trivyInstalled = ("$(& $TrivyExe --version 2>$null | Select-Object -First 1)" -replace '^Version:\s*', '').Trim()
$banditExe = Join-Path $ProjectRoot '.venv\Scripts\bandit.exe'
if (-not (Test-Path -LiteralPath $banditExe)) { Fail "bandit.exe missing at $banditExe" }
$banditInstalled = ("$(& $banditExe --version 2>$null | Select-Object -First 1)" -replace '^bandit\s+', '').Trim()

Write-Host ("installed: checkov {0} | trivy {1} | bandit {2}" -f $checkovInstalled, $trivyInstalled, $banditInstalled)
Write-Host ("requested: checkov {0} | trivy {1} | bandit {2}" -f $CheckovVersion, $TrivyVersion, $BanditVersion)

if ($checkovInstalled -ne $CheckovVersion) { Fail "venv checkov is $checkovInstalled, not $CheckovVersion - pip install checkov==$CheckovVersion first (into .venv)" }
if ($trivyInstalled  -ne $TrivyVersion)    { Fail "trivy at $TrivyExe is $trivyInstalled, not $TrivyVersion - put the new binary there first (docs/testing.md section 2)" }
if ($banditInstalled -ne $BanditVersion)   { Fail "venv bandit is $banditInstalled, not $BanditVersion - pip install bandit==$BanditVersion first" }

# Current pins as claimed by the tests (they are the source of truth for
# "what the fixtures were captured with").
$testText = [System.IO.File]::ReadAllText($TestFile)
$oldCheckov = if ($testText -match 'checkov_version"\] == "([^"]+)"') { $Matches[1] } else { Fail 'cannot find the checkov provenance assert in tests/test_runner.py' }
$oldTrivy   = if ($testText -match 'Trivy"\]\["Version"\] == "([^"]+)"') { $Matches[1] } else { Fail 'cannot find the trivy provenance assert in tests/test_runner.py' }
Write-Host ("fixture gates claim: checkov {0} | trivy {1}" -f $oldCheckov, $oldTrivy)

$unchanged = ($oldCheckov -eq $CheckovVersion) -and ($oldTrivy -eq $TrivyVersion)
if ($unchanged -and -not $Force) {
    Fail ("provenance gates already claim checkov {0} / trivy {1}; nothing to upgrade (use -Force to recapture anyway)" -f $oldCheckov, $oldTrivy)
}

# ---------------------------------------------------------------- scratch
$scratch = Join-Path $env:TEMP ("sr-fixrec-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {

# ---------------------------------------------------------------- capture
Step 'Capturing fresh scanner output from the fixture tree'
$capTree = Join-Path $scratch 'tree'
Copy-Item -Path $TreeDir -Destination $capTree -Recurse
# Restore the real name in the disposable copy (see header: the .fixture
# suffix exists so the repo's own CI scan gate cannot see this tree).
$fixtureFile = Join-Path $capTree 'main.tf.fixture'
if (-not (Test-Path -LiteralPath $fixtureFile)) { Fail "expected $fixtureFile in the fixture tree" }
Move-Item -Path $fixtureFile -Destination (Join-Path $capTree 'main.tf')
Write-Host "scan root: $capTree"

# One helper does both captures, writes the .new files itself (UTF-8, no
# BOM, byte-clean), normalizes trivy's machine-noise fields, and prints a
# summary. Plain argv - no shell, no quoting games. NOTE: checkov runs with
# the runner's exact JSON flags (--output json, NOT --compact): the fixture
# must be literally what the pinned scanner emits under the runner's argv.
$capturePy = Join-Path $scratch 'capture_fixtures.py'
@'
import json, subprocess, sys

venv_python, trivy_exe, scan_root, ck_out, tv_out = sys.argv[1:6]

# checkov: same argv shape the runner uses (target before --skip-path),
# minus the exclude flags: the fixture tree has no .venv to skip.
r = subprocess.run([venv_python, "-m", "checkov.main", "-d", scan_root, "-o", "json"],
                   capture_output=True, text=True, timeout=600)
if r.returncode not in (0, 1) or not r.stdout.strip():
    print("checkov capture failed:", r.returncode, (r.stderr or "")[-400:]); sys.exit(1)
raw = r.stdout
# Normalize capture-location noise the same way trivy's is. The catch:
# checkov emits these paths JSON-ESCAPED inside the raw text (backslashes
# doubled), so plain-text replaces never match - escape the variants the
# same way before replacing. checkov also derives a drive-and-user-less
# "repo" path (repo_file_path), so a final pass replaces the guid-bearing
# scratch dir NAME wherever it still appears. After the first normalized
# capture is committed, future recaptures diff only when scanner OUTPUT
# actually changes; the delta step makes anything odd visible.
# The scratch dir is scan_root's PARENT (scan_root ends in \\tree); its
# name is the random sr-fixrec-xxxx token that changes every run and also
# survives (drive-less) inside checkov's derived repo_file_path.
scratch_base = scan_root.rstrip("\\/").replace("/", "\\").split("\\")[-2]
variants = {scan_root, scan_root.replace("\\", "/")}
for v in variants:
    for form in (v, v.replace("\\", "\\\\")):
        raw = raw.replace(form, "<capture-dir>")
raw = raw.replace(scratch_base, "<capture-dir>")
# The fixture tree is the scratch dir's 'tree' child; once the scratch dir
# itself is <capture-dir>, the redundant leaf folds away (checkov's derived
# drive-less repo_file_path is the form that keeps it).
raw = raw.replace("<capture-dir>/tree/", "<capture-dir>/")
# checkov emits some string-array fields in nondeterministic order between
# runs (parallel scan workers): the per-check `details` tag list AND the
# graph-check `evaluated_keys`. Sort both in place, preserving the block's
# own whitespace, or consecutive recaptures diff by pure reordering.
import re
def _sort_array(key):
    def sort(m):
        inner = m.group(1)
        items = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
        if len(items) < 2:
            return m.group(0)
        ws = re.search(r'", (\s+)"', inner)
        # Quotes live on the ELEMENTS (each is wrapped "..."), never on the
        # separator: sep as '",<ws>"' doubles them ("a"",<ws>""b") and the
        # next json.loads dies. The whitespace-only sep keeps the block's
        # original indentation.
        sep = ',' + (ws.group(1) if ws else ' ')
        return '"' + key + '": [' + sep.join('"' + i + '"' for i in sorted(items)) + ']'
    return sort
for key in ('details', 'evaluated_keys'):
    raw = re.sub(r'"' + key + r'": \[(.*?)\]', _sort_array(key), raw, flags=re.S)
ck = json.loads(raw)
summary = ck.get("summary", {})
with open(ck_out, "w", encoding="utf-8", newline="") as f:
    f.write(raw)

r = subprocess.run([trivy_exe, "config", "--format", "json", scan_root],
                   capture_output=True, text=True, timeout=600)
if r.returncode != 0 or not r.stdout.strip():
    print("trivy capture failed:", r.returncode, (r.stderr or "")[-400:]); sys.exit(1)
tv = json.loads(r.stdout)
# Normalize ONLY machine noise; everything else stays verbatim.
tv["ArtifactName"] = "<capture-dir>"
tv["ReportID"] = "<report-id>"
tv["CreatedAt"] = "<created-at>"
misconfigs = sum(len(s.get("Misconfigurations", [])) for s in tv.get("Results", []))
with open(tv_out, "w", encoding="utf-8", newline="") as f:
    json.dump(tv, f, indent=2)
    f.write("\n")

print("checkov: version", summary.get("checkov_version"),
      "| failed", summary.get("failed"), "| passed", summary.get("passed"))
print("trivy:   version", tv.get("Trivy", {}).get("Version"), "| misconfigs", misconfigs)
if summary.get("failed", 0) < 1 or misconfigs < 1:
    print("fixture tree must produce at least one FAILED check per scanner"); sys.exit(1)
'@ | Set-Content -LiteralPath $capturePy -Encoding ascii

& $Python $capturePy $Python $TrivyExe $capTree "$($Fixtures.checkov).new" "$($Fixtures.trivy).new"
if ($LASTEXITCODE -ne 0) { Fail 'capture failed; nothing was changed' }

# ---------------------------------------------------------------- dry parse
Step 'Dry parse + rule-set delta (new captures vs committed fixtures)'
# sys.path insertion instead of pip-installing the package: the script must
# work even when the working tree is ahead of the installed copy.
$probePy = Join-Path $scratch 'probe.py'
@'
import json, sys
sys.path.insert(0, r"__PROJ__\src")
from secure_review import runner  # noqa: E402

proj = r"__PROJ__"
scratch = r"__SCRATCH__"
def ids(path, fn, scanner):
    doc = json.load(open(path, encoding="utf-8"))
    raw = json.dumps(doc)
    try:
        found = fn(raw, scanner)
    except Exception as e:
        print("PARSE-FAIL", scanner, type(e).__name__, e)
        return None
    return sorted({f.rule_id for f in found})

failed = False
for name, fn, scanner, newp, oldp in (
    ("checkov", runner._parse_checkov, "Checkov", "ck.new", "ck.old"),
    ("trivy",   runner._parse_trivy,   "Trivy config", "tv.new", "tv.old"),
):
    new = ids(scratch + "\\" + newp, fn, scanner)
    old = ids(scratch + "\\" + oldp, fn, scanner)
    if new is None or old is None or len(new) < 1:
        failed = True; continue
    gone, added = sorted(set(old) - set(new)), sorted(set(new) - set(old))
    status = "SAME   " if not gone and not added else "CHANGED"
    print(f"{name}: {status} {len(new)} rules now, was {len(old)}")
    if gone:
        print(f"  policies dropped: {gone}")
        print("  -> rule-set pins in tests/test_runner.py will fail; update them DELIBERATELY")
    if added:
        print(f"  policies added:   {added}  -> consider pinning them")
if failed:
    sys.exit(1)
'@.Replace('__PROJ__', $ProjectRoot).Replace('__SCRATCH__', $scratch) | Set-Content -LiteralPath $probePy -Encoding ascii

Copy-Item "$($Fixtures.checkov).new" (Join-Path $scratch 'ck.new')
Copy-Item "$($Fixtures.trivy).new"   (Join-Path $scratch 'tv.new')
Copy-Item $Fixtures.checkov          (Join-Path $scratch 'ck.old')
Copy-Item $Fixtures.trivy            (Join-Path $scratch 'tv.old')
& $Python $probePy
if ($LASTEXITCODE -ne 0) { Fail 'new fixtures do not parse into >=1 finding each; NOT flipping anything' }

# ---------------------------------------------------------------- pin flips
Step 'Flipping machine-verified pins'
function Replace-Literal([string]$path, [string]$old, [string]$new) {
    $text = [System.IO.File]::ReadAllText($path)
    $updated = $text.Replace($old, $new)
    if ($updated -ceq $text) { return 0 }
    [System.IO.File]::WriteAllText($path, $updated, (New-Object System.Text.UTF8Encoding($false)))
    return 1
}

$flips = 0
# 1) provenance asserts in the tests
$flips += Replace-Literal $TestFile ('checkov_version"] == "' + $oldCheckov + '"') ('checkov_version"] == "' + $CheckovVersion + '"')
$flips += Replace-Literal $TestFile ('Trivy"]["Version"] == "' + $oldTrivy + '"') ('Trivy"]["Version"] == "' + $TrivyVersion + '"')
# 2) workflow pip pins (scan job + e2e job use the same literal line)
$flips += Replace-Literal $Workflow ('"checkov==' + $oldCheckov + '" "bandit==1.9.4"') ('"checkov==' + $CheckovVersion + '" "bandit==' + $BanditVersion + '"')
# 3) trivy: setup-trivy version (x2), download URL, and the zip SHA-256.
#    The hash CANNOT be matched with a global 64-hex search: the lint job's
#    actionlint/shellcheck pins are also 64-hex strings, and replacing those
#    would corrupt the lint job (a first cut of this script did exactly
#    that). Scope the extraction to the e2e step's own line, then literal-
#    replace that one hash with the fresh one.
$flips += Replace-Literal $Workflow ('version: v' + $oldTrivy) ('version: v' + $TrivyVersion)
$oldUrl = 'https://github.com/aquasecurity/trivy/releases/download/v' + $oldTrivy + '/trivy_' + $oldTrivy + '_windows-64bit.zip'
$newUrl = 'https://github.com/aquasecurity/trivy/releases/download/v' + $TrivyVersion + '/trivy_' + $TrivyVersion + '_windows-64bit.zip'
$flips += Replace-Literal $Workflow $oldUrl $newUrl

$zipPath = Join-Path $scratch ("trivy_" + $TrivyVersion + "_windows-64bit.zip")
Write-Host "downloading $newUrl (to pin its SHA-256)..."
$ProgressPreference = 'SilentlyContinue'   # IWR without this draws progress-bar cost in PS 5.1
Invoke-WebRequest -Uri $newUrl -OutFile $zipPath
$ProgressPreference = 'Continue'
$newHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$wfText = [System.IO.File]::ReadAllText($Workflow)
$hashMatch = [regex]::Match($wfText, "if \(\`$hash -ne '([0-9a-fA-F]{64})'\)")
if (-not $hashMatch.Success) { Fail 'cannot find the trivy zip hash line (if ($hash -ne ...) { exit 1 }) in the workflow' }
$flips += Replace-Literal $Workflow $hashMatch.Groups[1].Value $newHash.ToLower()
Write-Host ("trivy zip SHA-256 pinned: {0} ({1} workflow flip(s) total)" -f $newHash.ToLower(), $flips)

# runner.py comment pins are empirical-behavior claims this script cannot
# re-verify -> they are listed in the final checklist, never rewritten here.

# ---------------------------------------------------------------- promote
Step 'Promoting fixtures'
Move-Item -Force -Path "$($Fixtures.checkov).new" -Destination $Fixtures.checkov
Move-Item -Force -Path "$($Fixtures.trivy).new"   -Destination $Fixtures.trivy

# ---------------------------------------------------------------- suite
Step 'Running the suite (the gate that decides)'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ProjectRoot 'run-tests.ps1')
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Fail "suite failed ($LASTEXITCODE). Likely causes: parser shape drift (fix _parse_* deliberately) or changed rule sets (update the by_rule pins). No commit made."
}

# ---------------------------------------------------------------- commit
$changedFiles = @('tests/fixtures/checkov_real.json', 'tests/fixtures/trivy_real.json',
    'tests/test_runner.py', '.github/workflows/secure-review.yml') |
    Where-Object { git -C $ProjectRoot status --porcelain -- $_ }

if ($Commit) {
    if (-not $changedFiles) { Fail 'nothing to commit - pins and fixtures already match' }
    Step 'Committing'
    git -C $ProjectRoot add -- $changedFiles
    $msg = @"
Upgrade scanners: checkov $CheckovVersion, trivy v$TrivyVersion, bandit $BanditVersion

- fixtures recaptured verbatim from tests/fixtures/tree (trivy machine
  fields normalized: ArtifactName/ReportID/CreatedAt)
- provenance asserts + workflow pins (pip, setup-trivy, zip URL, zip
  SHA-256) flipped in the same commit
- suite green after the flip

🤖 Generated with Codebuff
Co-Authored-By: Codebuff <noreply@codebuff.com>
"@
    git -C $ProjectRoot commit -m $msg
    Write-Host "committed: $($changedFiles -join ', ')"
} else {
    Step 'Not committing (-Commit not passed)'
    Write-Host "changed: $(if ($changedFiles) { $changedFiles -join ', ' } else { '(none)' })"
}

# ---------------------------------------------------------------- checklist
Step 'Human checklist (the script cannot do these)'
$stale = git -C $ProjectRoot grep -n -e $oldCheckov -e "v$oldTrivy" -e $oldTrivy -e '1.9.4' -- 'docs' 'src' 'tests' 2>$null
if ($stale) {
    Write-Host "Prose/comment mentions of the OLD versions - review by hand (they are empirical claims, not pins):"
    $stale | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host '(no stale version mentions found in docs/src/tests)'
}
Write-Host @'
1. Update docs/testing.md counts if the finding total changed (e2e SARIF-OK N,
   the "last full run: N findings" line, section-4 expectations).
2. Run the e2e harness against the new scanners before pushing:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\e2e.ps1
   Expect 12 passed, 0 failed - and confirm the SARIF-OK count matches the
   docs numbers you just updated.
3. Update stale prose/comments listed above ONLY after re-verifying the
   claim against the new scanner (run the snippet, look at the output).
4. Push and watch:  gh pr checks <N> --watch
'@

} finally {
    Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
}
Write-Host "`ndone."
