"""Command-line interface for secure-review."""

import argparse
from pathlib import Path

from secure_review import __version__
from secure_review.findings import SEVERITY_ORDER, severity_rank
from secure_review.runner import ScannerResult, scan_path
from secure_review.sarif import to_json

USAGE_LINE = "usage: secure-review scan PATH  (runs Checkov, Trivy config, and Bandit)"


def _is_tool_error(result: ScannerResult) -> bool:
    """Execution problems never ran the scanner (no exit code).

    A nonzero exit WITH a code means the scanner ran and possibly found
    issues (bandit/checkov exit nonzero on findings) - that is threshold
    territory, not a tool error.
    """
    if result.status in {"missing", "timeout"}:
        return True
    return result.status == "failed" and result.exit_code is None


def _print_summary_line(result: object) -> None:
    if not isinstance(result, ScannerResult):
        print(f"- unknown runner output: {result!r}")
        return
    if result.finding is not None:
        f = result.finding
        print(f"- {f.scanner}: finding {f.rule_id} ({f.severity}) {f.path}:{f.line}")
        return
    line = f"- {result.scanner}: {result.status}"
    if result.exit_code is not None:
        line += f" (exit {result.exit_code})"
    print(line)


def _write_sarif(sarif_path: Path, findings: list) -> bool:
    """Best effort: a report-write failure warns but never changes the exit."""
    try:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(to_json(findings), encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write SARIF report {sarif_path}: {exc}")
        return False
    return True


def _run_scan(path: Path, fail_on: str, sarif_path: Path | None = None) -> int:
    if not path.exists():
        print(f"error: path does not exist: {path}")
        return 2
    if not path.is_dir():
        print(f"error: not a directory: {path}")
        return 2
    print(f"Scan started: {path}")
    try:
        results = scan_path(path)
        if not isinstance(results, list):
            print(f"- unexpected runner output: {results!r}")
            return 0
    except Exception as exc:  # defensive: report, never crash the CLI
        print(f"- runner error: {exc!r}")
        return 1

    for result in results:
        _print_summary_line(result)

    # The report is emitted on every outcome that ran scanners (0/1/3) so
    # CI gets artifacts even from failed gates; exit 2 (invalid path)
    # never reaches a scan and writes nothing.
    if sarif_path is not None:
        findings = [r.finding for r in results if isinstance(r, ScannerResult) and r.finding is not None]
        _write_sarif(sarif_path, findings)

    if any(isinstance(r, ScannerResult) and _is_tool_error(r) for r in results):
        # Scanner execution problems are distinct from threshold failures:
        # they exit 1 regardless of --fail-on, and no threshold is evaluated.
        print("scan failure: a scanner was missing, timed out, or failed to run")
        return 1

    findings = [r.finding for r in results if isinstance(r, ScannerResult) and r.finding is not None]
    worst = max((severity_rank(f.severity) for f in findings), default=0)
    worst_name = SEVERITY_ORDER[worst] if worst < len(SEVERITY_ORDER) else "unknown"
    print(f"worst severity: {worst_name}")
    # Breach iff any finding meets or exceeds the threshold. With the
    # default (none) this means: exit 3 iff there is any finding at all.
    if any(severity_rank(f.severity) >= severity_rank(fail_on) for f in findings):
        print(f"fail-on {fail_on}: threshold met or exceeded")
        return 3
    print(f"fail-on {fail_on}: below threshold")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secure-review",
        description="Run security scanners over a codebase.",
        epilog=(
            "scan exits: 0 clean (or below threshold), 1 scanner execution "
            "problem (missing/timeout/failed), 2 invalid path, 3 findings "
            "met or exceeded --fail-on."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Run security scanners against a directory.")
    scan_parser.add_argument("path", type=Path, help="Directory to scan.")
    scan_parser.add_argument(
        "--sarif",
        type=Path,
        default=None,
        help="Write a SARIF 2.1.0 report of the parsed findings to this path.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="none",
        help=(
            "Exit 3 when findings meet or exceed this severity "
            "(default: none = any finding fails; "
            "critical = only critical findings fail)."
        ),
    )
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args.path, args.fail_on, args.sarif)
    print(USAGE_LINE)
    return 0
