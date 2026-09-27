"""Tests for the dynamic version wired through pyproject.toml."""

import tomllib
from pathlib import Path

import secure_review


def test_pyproject_version_is_dynamic_from_package():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as f:
        config = tomllib.load(f)

    assert config["project"]["name"] == "secure-review"
    assert config["project"]["dynamic"] == ["version"]
    assert "version" not in config["project"]
    attr = config["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "secure_review.__version__"
    assert secure_review.__version__ == "0.1.0"
