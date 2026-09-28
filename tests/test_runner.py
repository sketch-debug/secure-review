"""Tests for the scanner runner seam. All scanner execution is mocked."""

import json
import subprocess
from dataclasses import dataclass, field

import pytest

from secure_review import runner


@dataclass
class FakeRun:
    """Stands in for subprocess.run, recording every call and its kwargs."""

    calls: list = field(default_factory=list)
    exit_code: int = 0
    exit_codes: dict = field(default_factory=dict)  # per-scanner overrides
    stdout: str = ""
    stdout_by: dict = field(default_factory=dict)  # per-scanner JSON output
    raise_: Exception | None = None

    def __call__(self, cmd, **kwargs):
        self.calls.append({"cmd": cmd, **kwargs})
        if self.raise_ is not None:
            raise self.raise_
        code = self.exit_codes.get(cmd[0], self.exit_code)
        return subprocess.CompletedProcess(cmd, code, self.stdout_by.get(cmd[0], self.stdout), b"")


@pytest.fixture
def scanner_env(monkeypatch):
    """Pretend every scanner binary exists; capture subprocess.run calls."""
    fake = FakeRun()
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/fake/" + name)
    monkeypatch.setattr(runner.subprocess, "run", fake)
    return fake


def test_missing_binary_is_reported_without_running(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    results = runner.scan_path(tmp_path)
    assert [(r.scanner, r.status, r.exit_code) for r in results] == [
        ("Checkov", "missing", None),
        ("Trivy config", "missing", None),
        ("Bandit", "missing", None),
    ]


def test_success_and_failure_exit_codes(tmp_path, scanner_env):
    scanner_env.exit_codes = {"checkov": 0, "trivy": 3, "bandit": 3}
    results = runner.scan_path(tmp_path)

    assert [r.status for r in results] == ["success", "failed", "failed"]
    assert [r.exit_code for r in results] == [0, 3, 3]
    assert len(scanner_env.calls) == 3


def test_timeout_is_reported(tmp_path, scanner_env):
    scanner_env.raise_ = subprocess.TimeoutExpired("checkov", 300)
    results = runner.scan_path(tmp_path)

    assert all(r.status == "timeout" and r.exit_code is None for r in results)


def test_timeout_parameter_is_forwarded_and_defaults(tmp_path, scanner_env):
    runner.scan_path(tmp_path, timeout_seconds=2)
    assert scanner_env.calls[0]["timeout"] == 2

    runner.scan_path(tmp_path)
    assert scanner_env.calls[-1]["timeout"] == runner.DEFAULT_TIMEOUT_SECONDS


def test_oserror_is_reported_as_failed(tmp_path, scanner_env):
    scanner_env.raise_ = OSError("spawn failed")
    results = runner.scan_path(tmp_path)

    assert all(r.status == "failed" and r.exit_code is None for r in results)


def test_findings_exit_code_is_preserved(tmp_path, scanner_env):
    """A scanner that ran and exited nonzero (findings) keeps its exit code."""
    scanner_env.exit_code = 1  # e.g. bandit exits 1 when it finds issues
    results = runner.scan_path(tmp_path)

    assert all(r.status == "failed" and r.exit_code == 1 for r in results)


def test_findings_differ_from_execution_failures(tmp_path, scanner_env):
    """exit_code is the discriminator: findings preserve it, failures have None."""
    scanner_env.exit_code = 1
    findings = runner.scan_path(tmp_path)

    scanner_env.raise_ = OSError("spawn failed")
    failures = runner.scan_path(tmp_path)

    assert [(r.status, r.exit_code) for r in findings] == [("failed", 1)] * 3
    assert [(r.status, r.exit_code) for r in failures] == [("failed", None)] * 3


def test_scanners_run_as_argument_list_without_shell(tmp_path, scanner_env):
    runner.scan_path(tmp_path)

    scanner_flags = {"checkov": ["-d"], "trivy": ["config"], "bandit": ["-r"]}
    assert [c["cmd"][0] for c in scanner_env.calls] == ["checkov", "trivy", "bandit"]
    for call in scanner_env.calls:
        cmd = call["cmd"]
        assert isinstance(cmd, list), "scanner command must be an argument list"
        assert not call.get("shell", False), "must not run through the shell"
        assert call["capture_output"] is True
        assert call["text"] is True
        assert cmd[1:-1] == scanner_flags[cmd[0]]
        assert cmd[-1] == str(tmp_path)


BANDIT_JSON = json.dumps(
    {"results": [
        {"test_id": "B602", "issue_severity": "HIGH", "issue_text": "shell=True",
         "filename": "app/run.py", "line_number": 14},
        {"test_id": "B101", "issue_severity": "LOW", "issue_text": "assert",
         "filename": "app/t.py", "line_number": "3"},
    ]}
)
CHECKOV_JSON = json.dumps([
    {"failed_check": [{"check_id": "CKV_AWS_1", "severity": "CRITICAL",
                       "check_name": "IAM allows *", "file_path": "main.tf",
                       "file_line_end": 7}]},
])
TRIVY_JSON = json.dumps({"Results": [
    {"Target": "deploy.yaml",
     "Misconfigurations": [{"ID": "AVD-001", "Severity": "MEDIUM",
                            "Title": "privileged",
                            "CauseMetadata": {"StartLine": 9}}]},
]})


def test_parser_shapes_are_pinned(tmp_path, scanner_env):
    scanner_env.stdout_by = {
        "checkov": CHECKOV_JSON,
        "trivy": TRIVY_JSON,
        "bandit": BANDIT_JSON,
    }
    results = runner.scan_path(tmp_path)

    findings = [r.finding for r in results if r.status == "finding"]
    by_rule = {f.rule_id: f for f in findings}

    bandit = by_rule["B602"]
    assert (bandit.scanner, bandit.severity, bandit.path, bandit.line) == (
        "Bandit", "HIGH", "app/run.py", 14)
    assert by_rule["B101"].line is None  # non-int line number dropped

    checkov = by_rule["CKV_AWS_1"]
    assert (checkov.scanner, checkov.severity, checkov.path, checkov.line) == (
        "Checkov", "CRITICAL", "main.tf", 7)

    trivy = by_rule["AVD-001"]
    assert (trivy.scanner, trivy.severity, trivy.path, trivy.line) == (
        "Trivy config", "MEDIUM", "deploy.yaml", 9)


def test_success_with_unparseable_json_is_a_tool_failure(tmp_path, scanner_env):
    scanner_env.stdout_by = {"checkov": "<not json>"}
    results = runner.scan_path(tmp_path)

    checkov = [r for r in results if r.scanner == "Checkov"]
    assert any(r.status == "failed" and r.exit_code is None for r in checkov)
    note = [r.finding for r in checkov if r.finding is not None]
    assert note[0].rule_id == "secure-review/missing-parse-output"
