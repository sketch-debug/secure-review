<#
.SYNOPSIS
    End-to-end behavioral test of secure-review's full exit-code contract on
    Windows, using the real CLI and real scanners (whatever is installed).

.DESCRIPTION
    Builds throwaway targets under %TEMP% and asserts, through the real
    console script, that the exit contract holds end to end:

        0  clean or below --fail-on threshold
        1  scanner execution problem (missing / timeout / failed to run)
        2  invalid path (not a directory / does not exist)
        3  findings met or exceeded --fail-on

    Capability tiers, decided by what the environment offers:
    - FULL: all three scanners runnable. Because a single failed/missing
      scanner forces exit 1 (tool-error precedence), exit 3 requires every
      scanner to execute; only then are the exit-3 and exit-0 probes run.
    - REDUCED: trivy (not pip-installable) absent. The exit-1 probe is then
      REAL (scan reports the missing scanner); exit-3/exit-0 probes SKIP.
    - FULL mode also re-parses the scan through the library and asserts the
      emitted SARIF 2.1.0 log matches the parsed findings exactly.
    - Pass -SkipShim to force REDUCED mode deterministically (skips the
      checkov shim build even when csc.exe is available).
    - On machines where pip could not create checkov.exe (an apostrophe in
      the project path breaks the wrapper: this dev box), the script builds
      a thin checkov.exe shim with csc.exe that execs `python -m checkov.main`,
      mirroring the manual workaround. Skipped if csc.exe is unavailable.

    PowerShell 5.1-compatible. Exit 0 = no failures (skips allowed), 1 = any
    failed probe.

.PARAMETER TrivyDir
    Directory containing trivy.exe, prepended to PATH. Auto-detected from
    %TEMP%\trivy-bin when omitted.

.PARAMETER PythonExe
    Python interpreter used for the `python -m secure_review.cli` fallback
    and interpreter-relative scanner detection. Defaults to the repo venv
    interpreter when present, else `python` on PATH (CI installs the
    package into the setup-python interpreter).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e.ps1
#>

param(
    [string]$TrivyDir = '',
    # Python interpreter for the module fallback and scanner detection
    # (see .PARAMETER PythonExe). Auto-resolved when omitted.
    [string]$PythonExe = '',
    # Force REDUCED mode even when the environment could support FULL:
    # skips the csc.exe checkov shim build and the trivy-dependent probes.
    # Useful to prove the reduced path deterministically.
    [switch]$SkipShim
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:PassCount = 0
$Script:FailCount = 0
$Script:SkipCount = 0

function Write-Case {
    param([string]$Name, [int]$Expected, [int]$Actual)
    $mark = 'FAIL'
    if ($Actual -eq $Expected) { $mark = 'ok' }
    Write-Host ("  [{0}] {1} -> exit {2} (expected {3})" -f `
        $mark, $Name, $Actual, $Expected)
    if ($Actual -eq $Expected) { $Script:PassCount++ } else { $Script:FailCount++ }
}

function Write-Skip {
    param([string]$Name, [string]$Reason)
    Write-Host ("  [SKIP] {0} ({1})" -f $Name, $Reason)
    $Script:SkipCount++
}

# Runs the real console script (or python -m fallback). [ref]Out receives the
# captured output; returns the process exit code. Does NOT stop on nonzero.
function Invoke-SecureReview {
    param([string]$ArgLine, [ref]$Out)
    $argList = @($ArgLine -split '\s+' | Where-Object { $_ })
    $cli = Join-Path $ProjectRoot '.venv\Scripts\secure-review.exe'
    $Out.Value = @()
    if (Test-Path -LiteralPath $cli) {
        $proc = Start-Process -FilePath $cli -ArgumentList $argList `
            -NoNewWindow -Wait -PassThru -WorkingDirectory $ProjectRoot `
            -RedirectStandardOutput "$Script:Tmp\out.txt" `
            -RedirectStandardError  "$Script:Tmp\err.txt"
        $Out.Value = @(Get-Content -LiteralPath "$Script:Tmp\out.txt")
        return $proc.ExitCode
    }
    # Fallback: run the module through a known interpreter (repo venv when
    # present, else python on PATH - on CI the package is installed into
    # the setup-python interpreter). Without -m, the fallback would exit 0
    # having done nothing, so every probe would silently "pass".
    $Out.Value = @(& $Script:Python -m secure_review.cli @argList 2>&1)
    return $LASTEXITCODE
}

# Asserts that a probe's captured stdout includes all substrings.
function Assert-OutputContains {
    param([string]$Name, [string[]]$Needles, [string[]]$Lines)
    $missing = @()
    foreach ($n in $Needles) {
        if (-not ($Lines -match [regex]::Escape($n))) { $missing += $n }
    }
    $mark = 'ok'
    if ($missing.Count -gt 0) { $mark = 'FAIL' }
    Write-Host ("  [{0}] {1} output mentions expected markers" -f $mark, $Name)
    if ($missing.Count -gt 0) {
        Write-Host ("       missing: {0}" -f ($missing -join ' | '))
        $Script:FailCount++
    } else {
        $Script:PassCount++
    }
}

# Counts findings of the form "- <scanner>: finding ..." in captured lines.
function Count-Findings {
    param([string[]]$Lines)
    return @($Lines | Where-Object { $_ -match ': finding ' }).Count
}

# ----------------------------- setup ------------------------------------

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName

# Interpreter for the CLI fallback and sysconfig-based scanner detection.
if ($PythonExe) {
    $Script:Python = $PythonExe
} else {
    $Script:Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $Script:Python)) { $Script:Python = 'python' }
}

# Mimic an activated venv: the runner resolves checkov/bandit via PATH
# (shutil.which), and a developer runs secure-review from an activated
# shell. Without this, scanners installed in .venv are invisible and every
# scan degenerates to exit 1 (missing).
$venvScripts = Join-Path $ProjectRoot '.venv\Scripts'
if (Test-Path -LiteralPath $venvScripts) {
    $env:Path = "$venvScripts;$env:Path"
}

$Script:Tmp = Join-Path $env:TEMP ("sr-e2e-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $Script:Tmp | Out-Null
$Target = Join-Path $Script:Tmp 'target'
$Clean = Join-Path $Script:Tmp 'clean'
New-Item -ItemType Directory -Path $Target | Out-Null
New-Item -ItemType Directory -Path $Clean | Out-Null

# --- trivy resolution (full mode needs it; it is not pip-installable) ----
if (-not $TrivyDir) {
    $candidate = Join-Path $env:TEMP 'trivy-bin'
    if (Test-Path -LiteralPath (Join-Path $candidate 'trivy.exe')) {
        $TrivyDir = $candidate
    }
}
$trivyPresent = $false
if ($TrivyDir -and (Test-Path -LiteralPath (Join-Path $TrivyDir 'trivy.exe'))) {
    $env:Path = "$TrivyDir;$env:Path"
    $trivyPresent = $true
} else {
    # Fall back to a trivy already on PATH (setup-trivy on CI; -SkipShim
    # does not disable this - it only skips the checkov shim build).
    $trivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
    if ($null -ne $trivyCmd) { $trivyPresent = $true }
}

# --- checkov runnability: what matters is a launchable executable ---------
# The runner (and any subprocess) launches console executables; .cmd/.ps1
# wrappers are NOT launchable that way. Detect via Python's own install
# layout (sysconfig scripts dir), which works in venvs AND CI layouts
# where Get-Command's PATH scan proved unreliable, with a PATH fallback.
$checkovRunnable = $false
$needShim = $false
$pyScripts = & $Script:Python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
if ($LASTEXITCODE -eq 0 -and $pyScripts) {
    $pyScripts = [string]$pyScripts
    foreach ($name in @('checkov.exe', 'checkov')) {
        $candidate = Join-Path $pyScripts $name
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        if ($name -eq 'checkov.exe') {
            $checkovRunnable = $true
        } else {
            # Non-exe script present without an exe shim target.
            $needShim = $true
        }
        break
    }
}
if (-not ($checkovRunnable -or $needShim)) {
    $checkovCmd = Get-Command checkov -ErrorAction SilentlyContinue
    if ($null -ne $checkovCmd) {
        $src = [string]$checkovCmd.Source
        if ($src -match '\.[eE][xX][eE]$') {
            $checkovRunnable = $true
        } elseif ($src -match '\.[cC][mM][dD]$') {
            $needShim = $true
        }
    }
}
if ($needShim -and -not $SkipShim) {
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) {
        $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    $pyExe = $Script:Python
    if ($pyExe -eq 'python') {
        $resolved = Get-Command python -ErrorAction SilentlyContinue
        if ($null -eq $resolved) { $pyExe = '' } else { $pyExe = $resolved.Source }
    }
    if ($pyExe -and (Test-Path -LiteralPath $csc) -and (Test-Path -LiteralPath $pyExe)) {
        $binDir = Join-Path $Script:Tmp 'bin'
        New-Item -ItemType Directory -Path $binDir | Out-Null
        $cs = @'
using System;
using System.Diagnostics;
using System.Text;

class CheckovShim
{
    static int Main(string[] args)
    {
        // Verbatim literal: the embedded path contains backslashes, and
        // \U in a regular literal is an illegal escape (CS1009).
        string python = @"__PYPATH__";
        var sb = new StringBuilder("-m checkov.main");
        foreach (string a in args)
        {
            sb.Append(" \"");
            sb.Append(a.Replace("\"", "\\\""));
            sb.Append("\"");
        }
        var psi = new ProcessStartInfo();
        psi.FileName = python;
        psi.Arguments = sb.ToString();
        psi.UseShellExecute = false;
        Process p;
        try { p = Process.Start(psi); }
        catch (Exception) { return 127; }
        p.WaitForExit();
        return p.ExitCode;
    }
}
'@
        $cs = $cs.Replace('__PYPATH__', $pyExe)
        Set-Content -LiteralPath (Join-Path $binDir 'shim.cs') -Value $cs -Encoding ascii
        $cscOut = & $csc -nologo "-out:$binDir\checkov.exe" "$binDir\shim.cs" 2>&1
        if (Test-Path -LiteralPath (Join-Path $binDir 'checkov.exe')) {
            $env:Path = "$binDir;$env:Path"
            $checkovRunnable = $true
            Write-Host ("checkov shim built at {0} (pip .cmd wrapper is not executable)" -f $binDir)
        } else {
            Write-Host ("checkov shim build FAILED: {0}" -f ($cscOut -join '; '))
        }
    }
}

# Full mode = every scanner the CLI expects can actually execute.
$fullMode = $checkovRunnable -and $trivyPresent

Write-Host ("e2e target: {0}" -f $Target)
Write-Host ("mode: {0} (checkov runnable: {1}; trivy present: {2})" -f `
    $(if ($fullMode) { 'FULL' } else { 'REDUCED' }), $checkovRunnable, $trivyPresent)

# Vulnerable Python target: B602 (HIGH), B607 (LOW), B105 (LOW).
New-Item -ItemType Directory -Path (Join-Path $Target 'pkg') | Out-Null
@"
import subprocess

def run(cmd):
    return subprocess.check_output(cmd, shell=True)

def verify(token):
    if token == 'hardcoded-admin-password-123':
        return True
    return False
"@ | Set-Content -LiteralPath (Join-Path $Target 'pkg\insecure.py') -Encoding ascii

# Vulnerable Terraform target: checkov/trivy config findings, incl. HIGH.
New-Item -ItemType Directory -Path (Join-Path $Target 'infra') | Out-Null
@"
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-prod-logs"
  acl    = "public-read"
}

resource "aws_security_group_rule" "open_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-00000000"
}
"@ | Set-Content -LiteralPath (Join-Path $Target 'infra\main.tf') -Encoding ascii

# Clean target.
Set-Content -LiteralPath (Join-Path $Clean 'trivial.py') -Value "x = 1`n" -Encoding ascii

# ----------------------------- probes -----------------------------------

Write-Host ''
Write-Host 'Probes:'

# --- 2: invalid path (never needs scanners) ---
$out = [ref]@()
$code = Invoke-SecureReview -ArgLine "scan $Script:Tmp\does-not-exist --fail-on none" -Out $out
Write-Case -Name 'exit 2: path does not exist' -Expected 2 -Actual $code
Assert-OutputContains -Name 'exit 2' -Needles @('error: path does not exist') -Lines $out.Value

$code = Invoke-SecureReview -ArgLine "scan $Script:Tmp\out.txt --fail-on none" -Out $out
Write-Case -Name 'exit 2: path is a file, not a directory' -Expected 2 -Actual $code
Assert-OutputContains -Name 'exit 2 (file)' -Needles @('error: not a directory') -Lines $out.Value

# --- 3: threshold (needs every scanner runnable; see $fullMode) ---------
if ($fullMode) {
    $code = Invoke-SecureReview -ArgLine "scan $Target --fail-on high" -Out $out
    Write-Case -Name 'exit 3: --fail-on high on vulnerable tree' -Expected 3 -Actual $code
    Assert-OutputContains -Name 'exit 3' `
        -Needles @('worst severity:', 'threshold met or exceeded') -Lines $out.Value
    $nf = Count-Findings -Lines $out.Value
    Write-Host ("  (informational) findings parsed: {0}" -f $nf)

    $code = Invoke-SecureReview -ArgLine "scan $Target --fail-on low" -Out $out
    Write-Case -Name 'exit 3: --fail-on low on vulnerable tree' -Expected 3 -Actual $code

    # --- 0: clean tree, default threshold (full mode only) --------------
    $code = Invoke-SecureReview -ArgLine "scan $Clean" -Out $out
    Write-Case -Name 'exit 0: clean tree, default threshold' -Expected 0 -Actual $code
    Assert-OutputContains -Name 'exit 0' `
        -Needles @('worst severity: none', 'below threshold') -Lines $out.Value
} else {
    Write-Skip -Name 'exit 3 probes + exit 0 probe' `
        -Reason 'need all scanners runnable (trivy and an executable checkov)'
}

# --- 1: scanner execution problem ---------------------------------------
# REDUCED mode: trivy missing -> the missing scanner is real, assert exit 1.
# FULL mode: with all scanners present the same command is a threshold
# exit 3 instead; true exit-1 behavior (missing/timeout) is covered by the
# stub-based unit tests in tests/test_cli.py.
if (-not $fullMode) {
    $code = Invoke-SecureReview -ArgLine "scan $Target --fail-on none" -Out $out
    Write-Case -Name 'exit 1: scanner missing (reduced mode)' -Expected 1 -Actual $code
    Assert-OutputContains -Name 'exit 1' `
        -Needles @('scan failure: a scanner was missing, timed out, or failed to run') -Lines $out.Value
} else {
    $code = Invoke-SecureReview -ArgLine "scan $Target --fail-on none" -Out $out
    Write-Case -Name 'exit 3: default threshold, all scanners installed' -Expected 3 -Actual $code
}

# --- SARIF 2.1.0 emission through the real library (full mode) ----------
if ($fullMode) {
    $probePy = $Script:Python
    $probe = Join-Path $Script:Tmp 'sarif_probe.py'
    @'
import json
import sys
from pathlib import Path

from secure_review.findings import Finding
from secure_review.runner import scan_path
from secure_review.sarif import to_json

target = Path(sys.argv[1])
results = scan_path(target)
findings = [r.finding for r in results if r.finding is not None]
assert findings, "no findings parsed; SARIF probe needs a vulnerable target"
log = json.loads(to_json(findings))
assert log["version"] == "2.1.0", log["version"]
assert log["$schema"].endswith("sarif-2.1.0.json")
run = log["runs"][0]
assert run["tool"]["driver"]["name"] == "secure-review"
assert len(run["results"]) == len(findings)
for res, finding in zip(run["results"], findings):
    assert res["ruleId"] == finding.rule_id
    assert res["level"] in ("none", "note", "warning", "error")
    assert res["properties"]["severity"] == finding.severity
    assert res["properties"]["scanner"] == finding.scanner
    assert res["message"]["text"] == finding.message
    if finding.path is not None:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == finding.path
        if finding.line is not None:
            assert loc["region"]["startLine"] == finding.line
print("SARIF-OK {0}".format(len(run["results"])))

# Best-effort validation against the OFFICIAL SARIF 2.1.0 schema.
# Three outcomes: SCHEMA-OK (pass), SCHEMA-UNAVAILABLE (validator
# missing or schemastore unreachable: skip, never a false failure),
# SCHEMA-FAIL (real validation error: nonzero exit -> probe fails).
try:
    import jsonschema
    import urllib.request
    with urllib.request.urlopen(
        "https://json.schemastore.org/sarif-2.1.0.json", timeout=10
    ) as fh:
        schema = json.load(fh)
except ImportError:
    print("SCHEMA-UNAVAILABLE jsonschema is not installed")
except (OSError, ValueError) as exc:
    print("SCHEMA-UNAVAILABLE {0}".format(exc))
else:
    try:
        jsonschema.validate(log, schema)
    except jsonschema.exceptions.ValidationError as exc:
        print("SCHEMA-FAIL {0}".format(exc.message))
        sys.exit(1)
    print("SCHEMA-OK")
'@ | Set-Content -LiteralPath $probe -Encoding ascii
    $sarifOut = @(& $probePy $probe $Target 2>&1)
    $sarifExit = $LASTEXITCODE
    if ($sarifExit -eq 0 -and @($sarifOut | Where-Object { $_ -match 'SARIF-OK \d+' }).Count -gt 0) {
        $Script:PassCount++
        $okLine = ($sarifOut | Where-Object { $_ -match 'SARIF-OK' } | Select-Object -First 1)
        Write-Host ("  [ok] SARIF 2.1.0 emission matches parsed findings ({0})" -f $okLine)
        $schemaLine = ($sarifOut | Where-Object { $_ -match 'SCHEMA-OK' } | Select-Object -First 1)
        if ($null -ne $schemaLine) {
            $Script:PassCount++
            Write-Host ("  [ok] SARIF log validates against the official 2.1.0 schema ({0})" -f $schemaLine)
        }
        $unavail = ($sarifOut | Where-Object { $_ -match 'SCHEMA-UNAVAILABLE' } | Select-Object -First 1)
        if ($null -ne $unavail) {
            Write-Skip -Name 'official-schema validation' -Reason ([string]$unavail)
        }
    } else {
        $Script:FailCount++
        Write-Host ("  [FAIL] SARIF 2.1.0 emission probe (exit {0})" -f $sarifExit)
        $sarifOut | ForEach-Object { Write-Host ("       {0}" -f $_) }
    }
}

# --------------------------- summary ------------------------------------

Write-Host ''
Write-Host ("e2e summary: {0} passed, {1} failed, {2} skipped" -f `
    $Script:PassCount, $Script:FailCount, $Script:SkipCount)
Remove-Item -LiteralPath $Script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($Script:FailCount -gt 0) { exit 1 }
exit 0
