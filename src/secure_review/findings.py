"""Normalized scanner findings, independent of any output format."""

from dataclasses import dataclass

# Ordered low to high; the names a --fail-on threshold accepts.
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    """One issue reported by a scanner, in scanner-native vocabulary."""

    scanner: str
    rule_id: str
    severity: str  # verbatim from the scanner; conversion must not alter it
    message: str
    path: str | None = None
    line: int | None = None


def severity_rank(severity: str) -> int:
    """Rank a severity name (case-insensitive); unknown names rank highest."""
    name = severity.strip().lower()
    if name in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(name)
    return len(SEVERITY_ORDER)
