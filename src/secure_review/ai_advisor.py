"""Optional AI advisor: explanations for scanner findings.

Design rules, enforced here rather than by convention:

- AI is **opt-in and off by default**: advising requires an explicit
  ``opt_in=True`` at construction, even when a client is configured.
  Without opt-in, or without a client, the scanner works unchanged and
  ``advise()`` returns ``None``.
- The advisor is read-only over findings: it never alters, suppresses,
  reprioritizes, or fixes them. Output is advisory only.
- Every provider call goes through :class:`AdvisorClient`, the single
  seam to mock or implement; this module never talks to a real provider.
- Provider responses are validated by :class:`Advisory` (unknown fields
  forbidden, so severity/suppression/patch semantics cannot be
  smuggled through); an invalid response — or a provider error such as
  a connection failure — degrades to *no advisory* and never raises
  into the scan path.

What metadata may be sent upstream
----------------------------------

Exactly these ``Finding`` fields, as plain strings, nothing else:
``scanner``, ``rule_id``, ``severity``, ``message``.

``path`` and ``line`` are deliberately **not** sent (decision, not
oversight): a path can embed a username or machine name, and neither
field improves an explanation enough to justify that disclosure.

Consequently **never sent**: source code, code snippets, full files,
environment variables, credentials — the ``Finding`` model has no field
that could carry any of these, :func:`metadata_for` sends only the
allowlisted fields, and it *rejects* (raises ``TypeError``) any Finding
that grows a field outside the allowlist-plus-exclusions set, so a
future field cannot leak silently.

``finding_id`` is generated locally from allowlisted fields plus a
short SHA-256 of the excluded location fields — deterministic, useful
for correlation, and it carries no raw path or line.

This module never logs request payloads or credentials.
"""

import hashlib
from dataclasses import dataclass, fields as dataclass_fields

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from secure_review.findings import Finding

# The enforced allowlist: exactly these Finding fields may reach a
# provider. See the module docstring for the path/line decision and
# the full data-flow contract.
ALLOWED_METADATA_FIELDS = frozenset({"scanner", "rule_id", "severity", "message"})

# Finding fields deliberately never sent upstream; documented above.
# metadata_for rejects anything outside ALLOWED + EXCLUDED.
EXCLUDED_METADATA_FIELDS = frozenset({"path", "line"})


class Advisory(BaseModel):
    """Validated advisor output. Scanner semantics cannot ride in here.

    Length limits keep provider output bounded (finding_id 1..512,
    explanation/likely_impact 1..4000, review_focus 1..2000 chars).
    ``extra="forbid"`` makes unknown fields a hard error, so a model
    cannot smuggle severity, suppression, or patch payloads through
    this type; ``frozen`` keeps one advisory immutable once accepted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    finding_id: str = Field(min_length=1, max_length=512)
    explanation: str = Field(min_length=1, max_length=4000)
    likely_impact: str = Field(min_length=1, max_length=4000)
    review_focus: str = Field(min_length=1, max_length=2000)


@dataclass(frozen=True)
class AdvisorRequest:
    """The metadata a client is allowed to send upstream for one finding."""

    finding_id: str
    metadata: dict[str, str]


def metadata_for(finding: Finding) -> dict[str, str]:
    """Extract only allowlisted Finding fields as plain strings.

    Raises ``TypeError`` when ``Finding`` has a field that is neither
    allowlisted nor a documented exclusion — future fields cannot leak
    by being added silently.
    """
    finding_fields = {f.name for f in dataclass_fields(type(finding))}
    unexpected = finding_fields - ALLOWED_METADATA_FIELDS - EXCLUDED_METADATA_FIELDS
    if unexpected:
        raise TypeError(f"unexpected finding fields outside the allowlist: {sorted(unexpected)}")
    return {field: str(getattr(finding, field)) for field in sorted(ALLOWED_METADATA_FIELDS)}


class AdvisorClient:
    """Provider seam: implement or mock this; never call it directly here.

    The default implementation is a stub that refuses to run, so an
    unconfigured advisor cannot silently call out to any service.
    """

    def advise(self, request: AdvisorRequest) -> Advisory:
        raise NotImplementedError(
            "no AI provider configured; implement AdvisorClient to enable advising"
        )


def _finding_id(finding: Finding) -> str:
    """Deterministic local id; embeds no raw path or line."""
    location = f"{finding.path}:{finding.line}" if finding.path is not None else str(finding.line)
    digest = hashlib.sha256(f"{location}:{finding.message}".encode("utf-8")).hexdigest()[:12]
    return f"{finding.scanner}/{finding.rule_id}/{digest}"


class Advisor:
    """Optional advisor facade. Inert unless a client AND opt-in are given."""

    def __init__(self, client: AdvisorClient | None = None, opt_in: bool = False) -> None:
        self._client = client
        self._opt_in = opt_in

    @property
    def enabled(self) -> bool:
        return self._opt_in and self._client is not None

    def advise(self, finding: Finding) -> Advisory | None:
        """Return a validated advisory for *finding*, or None.

        Disabled advisor (no client, or no explicit opt-in) -> None,
        and the client is never called. Provider output that fails
        Advisory validation, or a provider error (connection failure,
        timeout, ...), -> None as well: no advisory, nothing raised,
        and *finding* is never mutated — the caller keeps full
        ownership of scan results.
        """
        if not self.enabled:
            return None
        request = AdvisorRequest(finding_id=_finding_id(finding), metadata=metadata_for(finding))
        try:
            return Advisory.model_validate(self._client.advise(request))
        except ValidationError:
            return None  # malformed model output
        except Exception:
            return None  # provider error (connection, timeout, ...) — never propagate
