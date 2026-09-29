"""Pytest configuration for the secure-review suite.

Basetemp pin
------------
This machine's default pytest temp factory (%TEMP%\\pytest-of-<user>) is
poisoned: a crashed session left it with damaged ACLs that even an admin
shell could not remove. pytest's end-of-run cleanup then dies with
PermissionError AFTER all tests have passed, turning green suites red.

The root cause is undeletable, so the suite simply never touches that
tree: unless --basetemp is passed explicitly, every session is pointed at
a PID-suffixed scratch dir under %TEMP% instead (parallel-safe; the same
scheme run-tests.ps1 has always used -- its explicit flag still wins).

See docs/testing.md, "Windows quirks of this machine".
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace  # noqa: F401  (type-completeness only)

_PYTEST_OF_MARKER = "pytest-of"


def pytest_configure(config: SimpleNamespace) -> None:
    """Point pytest at a clean scratch dir unless --basetemp was given."""
    if config.option.basetemp is not None:
        return
    scratch = Path(tempfile.gettempdir()) / f"sr-pytest-{os.getpid()}"
    try:
        scratch.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # The pin is a workaround, not a requirement: if even %TEMP% is
        # broken, warn and let pytest use its default rather than crash.
        print(f"warning: could not create pytest basetemp {scratch}: {exc}")
        return
    config.option.basetemp = str(scratch)
