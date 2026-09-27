"""Smoke tests for the secure-review CLI."""

import secure_review.cli
from secure_review import __version__


def test_version_constant():
    assert __version__ == "0.1.0"


def test_main_returns_zero(capsys):
    assert secure_review.cli.main([]) == 0
    assert "no scanners configured yet" in capsys.readouterr().out
