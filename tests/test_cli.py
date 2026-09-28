"""Smoke tests for the secure-review CLI."""

import pytest

import secure_review.cli
from secure_review.findings import Finding
from secure_review.runner import ScannerResult


def test_main_returns_zero(capsys):
    assert secure_review.cli.main([]) == 0
    assert "usage: secure-review scan PATH" in capsys.readouterr().out


def test_scan_valid_directory(tmp_path, capsys):
    # No scanners installed here: a tool error (exit 1), not a threshold result.
    assert secure_review.cli.main(["scan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "Scan started:" in out
    for scanner in ("Checkov", "Trivy config", "Bandit"):
        assert f"- {scanner}: missing" in out


def test_scan_missing_path(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    assert secure_review.cli.main(["scan", str(missing)]) == 2
    assert "does not exist" in capsys.readouterr().out


def test_scan_rejects_file(tmp_path, capsys):
    target = tmp_path / "file.txt"
    target.write_text("x")
    assert secure_review.cli.main(["scan", str(target)]) == 2
    assert "not a directory" in capsys.readouterr().out


def test_scan_summaries_are_readable_for_every_status(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        secure_review.cli,
        "scan_path",
        lambda target: [
            ScannerResult("Checkov", "success", 0),
            ScannerResult("Bandit", "failed", 1),  # findings
            ScannerResult("Trivy config", "timeout", None),
            ScannerResult("Checkov", "missing", None),
            ScannerResult("Bandit", "failed", None),  # execution failure
        ],
    )
    assert secure_review.cli.main(["scan", str(tmp_path)]) == 1  # missing scanner = tool error
    out = capsys.readouterr().out
    assert "- Checkov: success (exit 0)" in out
    assert "- Bandit: failed (exit 1)" in out
    assert "- Trivy config: timeout" in out
    assert "- Checkov: missing" in out
    assert "- Bandit: failed\n" in out  # execution failure: no exit code


def test_scan_survives_malformed_runner_results(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(secure_review.cli, "scan_path", lambda target: [object(), None, 42])
    assert secure_review.cli.main(["scan", str(tmp_path)]) == 0
    assert capsys.readouterr().out.count("unknown runner output") == 3


def test_scan_survives_non_iterable_runner_results(tmp_path, capsys, monkeypatch):
    for bad in (None, 42):
        monkeypatch.setattr(secure_review.cli, "scan_path", lambda target, _bad=bad: _bad)
        assert secure_review.cli.main(["scan", str(tmp_path)]) == 0
        assert "unexpected runner output" in capsys.readouterr().out


def test_scan_survives_runner_exception(tmp_path, capsys, monkeypatch):
    def boom(target):
        raise RuntimeError("boom")

    monkeypatch.setattr(secure_review.cli, "scan_path", boom)
    assert secure_review.cli.main(["scan", str(tmp_path)]) == 1
    assert "runner error" in capsys.readouterr().out


# --- --fail-on threshold behavior -------------------------------------------


def _scan_with_findings(tmp_path, capsys, monkeypatch, severities):
    """Patch scan_path to return a clean run followed by the given findings."""
    payload = [ScannerResult("Bandit", "success", 0)]
    payload += [ScannerResult("Bandit", "finding", None, Finding("Bandit", "B1", s, "m", "a.py", 1)) for s in severities]
    monkeypatch.setattr(secure_review.cli, "scan_path", lambda target: payload)


def test_fail_on_none_exits_3_on_any_finding(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["LOW"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "none"]) == 3
    assert "threshold met or exceeded" in capsys.readouterr().out


def test_fail_on_medium_exits_3_for_medium(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["MEDIUM"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "medium"]) == 3


def test_fail_on_medium_passes_low(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["LOW"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "medium"]) == 0
    assert "below threshold" in capsys.readouterr().out


def test_fail_on_high_exits_3_for_high(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["HIGH"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "high"]) == 3


def test_fail_on_critical_only_fails_critical(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["HIGH", "CRITICAL"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "critical"]) == 3


def test_fail_on_critical_passes_high(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["HIGH"])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0


def test_unknown_severity_fails_every_threshold(tmp_path, capsys, monkeypatch):
    """An unrecognized severity must never be silently passed over."""
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["BANANA"])
    for threshold in ("none", "low", "medium", "high", "critical"):
        assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", threshold]) == 3, threshold
    assert "worst severity: unknown" in capsys.readouterr().out


def test_clean_scan_exits_zero_for_every_threshold(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(secure_review.cli, "scan_path", lambda target: [ScannerResult("Bandit", "success", 0)])
    for threshold in ("none", "low", "medium", "high", "critical"):
        assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", threshold]) == 0, threshold


def test_scan_failure_is_never_a_threshold_result(tmp_path, capsys, monkeypatch):
    """A missing scanner exits 1 even when --fail-on none and junk findings exist."""
    payload = [
        ScannerResult("Checkov", "missing", None),
        ScannerResult("Bandit", "failed", 1),
        ScannerResult("Bandit", "finding", None, Finding("Bandit", "B1", "CRITICAL", "m", "a.py", 1)),
    ]
    monkeypatch.setattr(secure_review.cli, "scan_path", lambda target: payload)
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "none"]) == 1
    assert "scan failure" in capsys.readouterr().out


def test_tool_error_exit_1_not_confused_with_threshold_exit_3(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(secure_review.cli, "scan_path", lambda target: [ScannerResult("Bandit", "timeout", None)])
    assert secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "none"]) == 1


def test_default_fail_on_is_none(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, ["LOW"])
    assert secure_review.cli.main(["scan", str(tmp_path)]) == 3  # default fires on any finding


def test_fail_on_rejects_unknown_choice(tmp_path, capsys, monkeypatch):
    _scan_with_findings(tmp_path, capsys, monkeypatch, [])
    with pytest.raises(SystemExit) as excinfo:
        secure_review.cli.main(["scan", str(tmp_path), "--fail-on", "apocalyptic"])
    assert excinfo.value.code == 2
