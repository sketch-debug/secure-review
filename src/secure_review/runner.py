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
    # Empirically pinned against checkov 3.3.20: single --output json
    # emits ONE dict {check_type, results: {failed_checks: [...]},
    # summary, url}; multiple formats emit a list of such dicts. Items
    # carry file_line_range [start, end] (file_line_end is None) and
    # severity is None per item, so it degrades to "unknown".
    document = json.loads(raw)
    sections = document if isinstance(document, list) else [document]
    findings = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        results = section.get("results") or {}
        for item in results.get("failed_checks", []):
            if not isinstance(item, dict):
                continue
            line_range = item.get("file_line_range") or []
            line = next((n for n in line_range if isinstance(n, int)), None)
            severity = item.get("severity")
            raw_path = item.get("file_path")
            findings.append(
                Finding(
                    scanner=scanner,
                    rule_id=str(item.get("check_id", "unknown")),
                    severity=str(severity) if severity else "unknown",
                    message=str(item.get("check_name", "")),
                    path=raw_path.lstrip("\\/") if isinstance(raw_path, str) else raw_path,
                    line=line,
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


# The scanner registry: one spec per scanner, parser attached. args
# MUST include the JSON-report flags (the single run's stdout is the
# parseable report) positioned so value-taking flags stay adjacent to
# their values. Tests pin parser shapes so scanner upgrades that change
# them fail loudly instead of silently losing findings.
SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec("Checkov", "checkov", ("--output", "json", "-d"), _parse_checkov),
    ScannerSpec("Trivy config", "trivy", ("config", "--format", "json"), _parse_trivy),
    ScannerSpec("Bandit", "bandit", ("-f", "json", "-r"), _parse_bandit),
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
            # Real scanners exit nonzero when they FIND issues (bandit,
            # checkov), so stdout is parsed for any executed scanner -
            # findings belong to nonzero exits too. Only execution
            # failures (timeout/OSError) have no stdout to parse.
            if completed.stdout:
                try:
                    parsed = spec.parser(completed.stdout, spec.name)
                except (json.JSONDecodeError, AttributeError, TypeError):
                    results.append(ScannerResult(spec.name, "failed", None))
                    parsed = [
                        Finding(
                            scanner=spec.name,
                            rule_id="secure-review/missing-parse-output",
                            severity="none",
                            message="scanner ran but its JSON output could not be parsed",
                        )
                    ]
                results.extend(ScannerResult(spec.name, "finding", None, finding) for finding in parsed)
    return results
