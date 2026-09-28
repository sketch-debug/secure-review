"""Tests for the optional AI advisor. No real provider is ever called."""

import json
import logging
from dataclasses import dataclass, replace

import pytest
from pydantic import ValidationError

from secure_review.ai_advisor import (
    ALLOWED_METADATA_FIELDS,
    EXCLUDED_METADATA_FIELDS,
    Advisory,
    Advisor,
    AdvisorClient,
    AdvisorRequest,
    metadata_for,
)
from secure_review.findings import Finding


def _finding() -> Finding:
    return Finding("Bandit", "B602", "HIGH", "shell=True", "app/run.py", 14)


def _valid_payload() -> dict:
    return {
        "finding_id": "Bandit/B602/0a1b2c3d4e5f",
        "explanation": "subprocess with shell=True enables command injection",
        "likely_impact": "remote code execution via crafted arguments",
        "review_focus": "replace shell=True with an argument list",
    }


class DictClient(AdvisorClient):
    """Mock provider returning raw payloads; records every request."""

    def __init__(self, payload) -> None:
        self.payload = payload
        self.requests: list[AdvisorRequest] = []

    def advise(self, request: AdvisorRequest):
        self.requests.append(request)
        return self.payload


# --- opt-in is required even with a client configured ------------------------


def test_client_alone_is_not_enough():
    client = DictClient(_valid_payload())
    advisor = Advisor(client)

    assert advisor.enabled is False
    assert advisor.advise(_finding()) is None
    assert client.requests == []  # provider never called


def test_opt_in_with_client_enables_advising():
    client = DictClient(_valid_payload())
    advisor = Advisor(client, opt_in=True)

    assert advisor.enabled is True
    assert isinstance(advisor.advise(_finding()), Advisory)


def test_no_client_stays_disabled_even_with_opt_in():
    advisor = Advisor(opt_in=True)
    assert advisor.enabled is False
    assert advisor.advise(_finding()) is None


# --- the allowlist is the enforced mechanism ---------------------------------


def test_request_contains_exactly_the_allowlisted_fields():
    client = DictClient(_valid_payload())
    Advisor(client, opt_in=True).advise(_finding())

    metadata = client.requests[0].metadata
    assert set(metadata) == ALLOWED_METADATA_FIELDS
    assert metadata == {
        "message": "shell=True",
        "rule_id": "B602",
        "scanner": "Bandit",
        "severity": "HIGH",
    }
    assert "path" not in metadata and "line" not in metadata


def test_path_and_line_never_reach_the_provider():
    """The path can embed a username; it is a documented exclusion."""
    finding = Finding("Bandit", "B602", "HIGH", "shell=True", r"C:\Users\jeffr\proj\run.py", 14)
    client = DictClient(_valid_payload())
    Advisor(client, opt_in=True).advise(finding)

    metadata = client.requests[0].metadata
    assert "jeffr" not in json.dumps(metadata)
    assert "run.py" not in json.dumps(metadata)
    assert "Users" not in json.dumps(metadata)
    # the local finding_id embeds only a digest of the location
    assert "jeffr" not in client.requests[0].finding_id
    assert "14" not in client.requests[0].finding_id


def test_future_non_allowlisted_finding_field_is_rejected():
    """A new Finding field must fail loudly, not leak silently."""

    @dataclass(frozen=True)
    class GrownFinding(Finding):
        code_snippet: str = "os.system(input())"  # pretend a field was added

    with pytest.raises(TypeError, match="code_snippet"):
        metadata_for(GrownFinding(scanner="Bandit", rule_id="B1", severity="HIGH", message="m"))


def test_metadata_never_serializes_source_or_secrets():
    finding = Finding(
        "Bandit", "B602", "HIGH", "shell=True",
        r"C:\Users\jeffr\proj\app\run.py", 14,
    )
    serialized = json.dumps(metadata_for(finding))

    for forbidden in ("os.system", "input()", "password", "API_KEY", "aws_secret", "env{", "os.environ"):
        assert forbidden not in serialized


# --- schema: full Prompt 2 battery (restored) ---------------------------------


def test_valid_payload_binds_to_frozen_model():
    advisory = Advisory.model_validate(_valid_payload())

    assert isinstance(advisory, Advisory)
    assert advisory.finding_id.startswith("Bandit/B602")
    with pytest.raises(ValidationError):
        advisory.explanation = "mutation attempt"  # frozen


def test_whitespace_only_fields_are_rejected():
    with pytest.raises(ValidationError):
        Advisory.model_validate(_valid_payload() | {"explanation": "   "})


@pytest.mark.parametrize("field", ["finding_id", "explanation", "likely_impact", "review_focus"])
def test_missing_field_is_rejected(field):
    payload = _valid_payload()
    del payload[field]
    with pytest.raises(ValidationError):
        Advisory.model_validate(payload)


@pytest.mark.parametrize("field", ["finding_id", "explanation", "likely_impact", "review_focus"])
def test_empty_field_is_rejected(field):
    with pytest.raises(ValidationError):
        Advisory.model_validate(_valid_payload() | {field: ""})


@pytest.mark.parametrize(
    ("field", "limit"),
    [("finding_id", 512), ("explanation", 4000), ("likely_impact", 4000), ("review_focus", 2000)],
)
def test_over_length_field_is_rejected(field, limit):
    with pytest.raises(ValidationError):
        Advisory.model_validate(_valid_payload() | {field: "x" * (limit + 1)})


@pytest.mark.parametrize(
    "smuggled",
    [
        {"severity": "LOW"},
        {"suppression": "ignore this finding"},
        {"patch": "os.system = safe_system"},
        {"fixed": True},
        {"severity": "LOW", "suppression": "none", "patch": ""},
        {"confidence": 0.9},
    ],
)
def test_unknown_and_smuggled_fields_are_rejected(smuggled):
    with pytest.raises(ValidationError):
        Advisory.model_validate(_valid_payload() | smuggled)


def test_wrong_types_are_rejected():
    with pytest.raises(ValidationError):
        Advisory.model_validate(_valid_payload() | {"likely_impact": 42})


def test_client_returning_prebuilt_advisory_passes_through():
    advisory = Advisory.model_validate(_valid_payload())
    assert Advisor(DictClient(advisory), opt_in=True).advise(_finding()) == advisory


# --- provider responses still validate and degrade safely (Prompt 2) ---------


@pytest.mark.parametrize(
    "bad",
    [
        {},
        _valid_payload() | {"explanation": ""},
        _valid_payload() | {"severity": "LOW"},
        _valid_payload() | {"patch": "os.system = safe_system"},
        None,
        42,
    ],
)
def test_invalid_provider_responses_degrade_to_no_advisory(bad):
    assert Advisor(DictClient(bad), opt_in=True).advise(_finding()) is None


def test_degradation_never_mutates_the_finding():
    finding = _finding()
    snapshot = replace(finding)

    assert Advisor(DictClient(_valid_payload() | {"patch": "rm -rf /"}), opt_in=True).advise(finding) is None
    assert finding == snapshot


# --- nothing payload-like is ever logged --------------------------------------


def test_advisor_logs_no_request_payload(caplog):
    finding = Finding("Bandit", "B602", "HIGH", "shell=True", r"C:\Users\jeffr\proj\run.py", 14)
    payload_markers = ("shell=True", "jeffr", "B602", "HIGH", "run.py")

    with caplog.at_level(logging.DEBUG):
        Advisor(DictClient(_valid_payload()), opt_in=True).advise(finding)
        Advisor(DictClient(_valid_payload() | {"patch": "x"}), opt_in=True).advise(finding)  # degrades
        Advisor().advise(finding)  # disabled path

    assert caplog.records == []
    text = caplog.text
    for marker in payload_markers:
        assert marker not in text


# --- provider errors degrade, never propagate ---------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ConnectionError("provider unreachable"),
        TimeoutError("provider timed out"),
        RuntimeError("SDK exploded"),
    ],
)
def test_provider_errors_degrade_to_no_advisory(error):
    class ExplodingClient(AdvisorClient):
        def advise(self, request: AdvisorRequest):
            raise error

    finding = _finding()
    snapshot = replace(finding)

    assert Advisor(ExplodingClient(), opt_in=True).advise(finding) is None
    assert finding == snapshot


def test_scan_cli_is_never_wired_to_the_advisor():
    """The scanner works unchanged without AI: no wiring exists at all."""
    import inspect
    from pathlib import Path

    import secure_review.cli as cli

    source = inspect.getsource(cli)
    assert "ai_advisor" not in source
    assert "Advisor" not in source
    # and the module's own scan contract is intact
    assert cli.main(["scan", str(Path("Z:/definitely/not/here"))]) == 2


# --- Prompt 1 contracts retained ----------------------------------------------


def test_default_client_refuses_to_run():
    with pytest.raises(NotImplementedError):
        AdvisorClient().advise(AdvisorRequest("id", {}))


def test_documented_field_sets_are_consistent():
    assert ALLOWED_METADATA_FIELDS | EXCLUDED_METADATA_FIELDS == {
        f.name for f in Finding.__dataclass_fields__.values()
    }
