"""Render normalized findings as SARIF 2.1.0.

Severity is never rewritten: results carry the scanner's severity
verbatim in `properties.severity`. `level` takes the scanner severity
when it is already a legal SARIF level, and SARIF's default "warning"
otherwise.
"""

import json

from secure_review import __version__
from secure_review.findings import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_LEVELS = frozenset({"none", "note", "warning", "error"})


def to_sarif(findings: list[Finding]) -> dict:
    """Convert findings into a SARIF 2.1.0 log; deterministic key order."""
    rules = []
    results = []
    for finding in findings:
        if not any(rule["id"] == finding.rule_id for rule in rules):
            rules.append({"id": finding.rule_id, "name": finding.rule_id})
        result = {
            "ruleId": finding.rule_id,
            "level": finding.severity if finding.severity in SARIF_LEVELS else "warning",
            "message": {"text": finding.message},
            "properties": {"severity": finding.severity, "scanner": finding.scanner},
        }
        if finding.path is not None:
            physical_location = {"artifactLocation": {"uri": finding.path}}
            if finding.line is not None:
                physical_location["region"] = {"startLine": finding.line}
            result["locations"] = [{"physicalLocation": physical_location}]
        results.append(result)

    driver = {"name": "secure-review", "version": __version__}
    if rules:
        driver["rules"] = rules
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def to_json(findings: list[Finding]) -> str:
    """Serialize the SARIF log deterministically (sorted keys, fixed indent)."""
    return json.dumps(to_sarif(findings), indent=2, sort_keys=True)
