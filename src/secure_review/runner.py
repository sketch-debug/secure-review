"""Execute external security scanners against a target path.

Statuses: "success" (exit 0), "missing" (binary not on PATH),
"timeout" (exceeded the per-scanner limit), "failed" (nonzero exit
or could not be executed), "finding" (one parsed result, carried in
`finding`).
"""

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from secure_review.findings import Finding

DEFAULT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class ScannerSpec:
    """Everything about one scanner: how to run it and how to read it.

    Adding or changing a scanner touches exactly one entry of SCANNERS
    below - never a second lookup table.
    """

    name: str
    binary: str
    args: tuple[str, ...]
    parser: Callable[[str, str], list[Finding]]  # (stdout, scanner name)


@dataclass(frozen=True)
class ScannerResult:
    scanner: str
    status: str  # "success" | "missing" | "timeout" | "failed" | "finding"
    exit_code: int | None  # None unless the scanner ran and exited
    finding: Finding | None = None  # set only when status == "finding"


def _parse_bandit(raw: str, scanner: str) -> list[Finding]:
    findings = []
    for item in json.loads(raw).get("results", []):
        if not isinstance(item, dict):
            continue
        line = item.get("line_number")
        findings.append(
            Finding(
                scanner=scanner,
                rule_id=str(item.get("test_id", "unknown")),
                severity=str(item.get("issue_severity", "unknown")),
                message=str(item.get("issue_text", "")),
                path=item.get("filename"),
                line=line if isinstance(line, int) else None,
            )
        )
    return findings


def _parse_checkov(raw: str, scanner: str) -> list[Finding]:
    # Checkov JSON: a list of results, one per framework/IaC type, each
    # with a failed_check list of {check_id, check_name, ...}.
    findings = []
    for section in json.loads(raw):
        if not isinstance(section, dict):
            continue
        for item in section.get("failed_check", []):
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    scanner=scanner,
                    rule_id=str(item.get("check_id", "unknown")),
                    severity=str(item.get("severity", "unknown")),
                    message=str(item.get("check_name", "")),
                    path=item.get("file_path"),
                    line=item.get("file_line_end"),
                )
            )
    return findings


def _parse_trivy(raw: str, scanner: str) -> list[Finding]:
    # Trivy JSON: {Results: [{Target, Misconfigurations: [{ID, Severity,
    # Title, CauseMetadata: {StartLine}}]}]}.
    findings = []
    for section in json.loads(raw).get("Results", []):
        if not isinstance(section, dict):
            continue
        target = section.get("Target")
        for item in section.get("Misconfigurations", []):
            if not isinstance(item, dict):
                continue
            cause = item.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    scanner=scanner,
                    rule_id=str(item.get("ID", "unknown")),
                    severity=str(item.get("Severity", "unknown")),
                    message=str(item.get("Title", "")),
                    path=target,
                    line=cause.get("StartLine"),
                )
            )
    return findings


# The scanner registry: one spec per scanner, parser attached. Tests pin
# parser shapes so scanner upgrades that change them fail loudly instead
# of silently losing findings.
SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec("Checkov", "checkov", ("-d",), _parse_checkov),
    ScannerSpec("Trivy config", "trivy", ("config",), _parse_trivy),
    ScannerSpec("Bandit", "bandit", ("-r",), _parse_bandit),
)


def scan_path(target: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> list[ScannerResult]:
    """Run every configured scanner against *target* and collect results."""
    target_str = str(target)
    results = []
    for spec in SCANNERS:
        if shutil.which(spec.binary) is None:
            results.append(ScannerResult(spec.name, "missing", None))
            continue
        try:
            completed = subprocess.run(
                [spec.binary, *spec.args, target_str],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            results.append(ScannerResult(spec.name, "timeout", None))
        except OSError:
            results.append(ScannerResult(spec.name, "failed", None))
        else:
            status = "success" if completed.returncode == 0 else "failed"
            results.append(ScannerResult(spec.name, status, completed.returncode))
            if status == "success" and completed.stdout:
                try:
                    parsed = spec.parser(completed.stdout, spec.name)
                except (json.JSONDecodeError, AttributeError, TypeError):
                    results.append(ScannerResult(spec.name, "failed", None))
                    parsed = [
                        Finding(
                            scanner=spec.name,
                            rule_id="secure-review/missing-parse-output",
                            severity="none",
                            message="scanner reported success but its JSON output could not be parsed",
                        )
                    ]
                results.extend(ScannerResult(spec.name, "finding", None, finding) for finding in parsed)
    return results
