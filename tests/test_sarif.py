"""Tests for the SARIF 2.1.0 adapter."""

import json

from secure_review.findings import Finding
from secure_review.sarif import SARIF_VERSION, to_json, to_sarif


def test_empty_findings_produce_empty_results():
    sarif = to_sarif([])
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["results"] == []
    assert "rules" not in run["tool"]["driver"]


def test_populated_findings_keep_rule_severity_location_message():
    findings = [
        Finding("Bandit", "B602", "HIGH", "subprocess with shell=True", "src/app/run.py", 14),
        Finding("Checkov", "CKV_AWS_1", "MEDIUM", "IAM policy allows *", "infra/main.tf", 7),
    ]
    sarif = to_sarif(findings)
    run = sarif["runs"][0]

    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["B602", "CKV_AWS_1"]
    assert len(run["results"]) == 2

    first = run["results"][0]
    assert first["ruleId"] == "B602"
    assert first["message"]["text"] == "subprocess with shell=True"
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/app/run.py"
    assert location["region"]["startLine"] == 14
    # severity: scanner vocabulary verbatim in properties; legal levels in level
    assert first["properties"]["severity"] == "HIGH"
    assert first["level"] == "warning"  # SARIF has no "HIGH"


def test_nonstandard_severity_never_rewrites_scanner_evidence():
    finding = Finding("Checkov", "CKV_1", "CRITICAL", "open security group")
    result = to_sarif([finding])["runs"][0]["results"][0]
    assert result["properties"]["severity"] == "CRITICAL"  # verbatim


def test_missing_optional_location_omits_locations_entirely():
    finding = Finding("Bandit", "B101", "LOW", "assert used", path=None, line=None)
    result = to_sarif([finding])["runs"][0]["results"][0]
    assert "locations" not in result

    path_only = Finding("Bandit", "B101", "LOW", "assert used", path="x.py", line=None)
    result = to_sarif([path_only])["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "x.py"
    assert "region" not in location


def test_output_is_deterministic_valid_json():
    findings = [Finding("Bandit", "B602", "HIGH", "shell=True", "a.py", 1)]
    first = to_json(findings)
    second = to_json(list(reversed(findings)))

    parsed = json.loads(first)
    assert first == second  # sorted keys + rule order make output stable
    assert parsed["runs"][0]["results"][0]["ruleId"] == "B602"
