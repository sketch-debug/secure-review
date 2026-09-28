<#
.SYNOPSIS
    Run the pytest suite with the project's venv python, from any directory.

.DESCRIPTION
    - Anchors on $PSScriptRoot, so the current directory is irrelevant: the
      script switches to the project root and runs pytest there.
    - Uses .venv\Scripts\python.exe when present; falls back to `python` on
      PATH (the CI layout, where the package is pip-installed into the
      setup-python interpreter).
    - Applies the basetemp workaround automatically: pytest gets its own
      scratch dir under %TEMP% (PID-suffixed, safe for parallel runs) so a
      poisoned %TEMP%\pytest-of-jeffr factory on this machine cannot break
      collection. The scratch dir is removed after a green run and kept
      for inspection after a red one.
    - Disables the pytest cache provider so the repo tree stays pristine.
    - Extra arguments pass straight through to pytest.

.EXAMPLE
    & "C:\Users\jeffr\jeff's Projects\SecureReview Agent\run-tests.ps1"

.EXAMPLE
    & "C:\Users\jeffr\jeff's Projects\SecureReview Agent\run-tests.ps1" -k threshold

.EXAMPLE
    .\run-tests.ps1 tests\test_cli.py -x

.NOTES
    Exit code = pytest's exit code (0 green, 1 failures, 2 interrupted,
    4 usage error), so CI or a local chain can rely on it directly.
#>

param(
    # Remaining arguments are forwarded to pytest verbatim.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PytestArgs
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = $PSScriptRoot

# Venv python when present, else python on PATH (CI layout).
$py = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = 'python' }

# PID-suffixed basetemp under %TEMP%: sidesteps a poisoned shared pytest
# factory, allows parallel invocations, and keeps the repo tree clean.
$basetemp = Join-Path $env:TEMP ("sr-pytest-" + $PID)

Write-Host ("pytest via {0} (project root: {1})" -f $py, $ProjectRoot)

$code = 1
Push-Location $ProjectRoot
try {
    & $py -m pytest -q -p no:cacheprovider "--basetemp=$basetemp" @PytestArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
    if ($null -ne $basetemp -and (Test-Path -LiteralPath $basetemp)) {
        if ($code -eq 0) {
            Remove-Item -LiteralPath $basetemp -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host ("pytest artifacts kept for inspection: {0}" -f $basetemp)
        }
    }
}

exit $code
