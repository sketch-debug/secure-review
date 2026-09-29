"""Contract tests for the root conftest.py basetemp pin.

The poisoned-factory bug was environmental: pytest's cleanup crashed at
TEARDOWN after all tests passed. So the tests here exercise two layers:

- unit: the hook's decision logic (redirect default, respect explicit);
- integration: a REAL nested bare `pytest -q` session (subprocess) that
  must exit 0 and never create a pytest-of-* factory dir, which is the
  exact scenario that used to fail green suites on this machine.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("root_conftest", PROJECT_ROOT / "conftest.py")
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)


def _stub_config(basetemp: str | None) -> types.SimpleNamespace:
    return types.SimpleNamespace(option=types.SimpleNamespace(basetemp=basetemp))


def test_hook_redirects_default_basetemp(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    config = _stub_config(basetemp=None)
    conftest.pytest_configure(config)
    expected = tmp_path / f"sr-pytest-{os.getpid()}"
    assert Path(config.option.basetemp) == expected
    assert expected.is_dir(), "scratch dir should exist before the session runs"


def test_hook_respects_explicit_basetemp(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    config = _stub_config(basetemp=str(tmp_path / "user-chosen"))
    conftest.pytest_configure(config)
    assert config.option.basetemp == str(tmp_path / "user-chosen")
    assert not (tmp_path / f"sr-pytest-{os.getpid()}").exists()


def _run_nested_bare_pytest(sandbox: Path) -> subprocess.CompletedProcess:
    """Run a minimal real pytest session in a sandbox repo that carries the
    root conftest.py - the closest reproduction of a developer's bare run."""
    (sandbox / "tests").mkdir(parents=True, exist_ok=True)
    (sandbox / "conftest.py").write_bytes((PROJECT_ROOT / "conftest.py").read_bytes())
    (sandbox / "tests" / "test_trivial.py").write_text(
        "def test_trivial():\n    assert True\n", encoding="utf-8"
    )
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        capture_output=True,
        text=True,
        cwd=sandbox,
        timeout=300,
    )


def test_bare_pytest_never_touches_poisoned_factory(tmp_path):
    # The real %TEMP% may already contain a poisoned pytest-of-<user> dir
    # (it is undeletable on this machine), so assert on DELTAS: the nested
    # bare session must not ADD any factory dir.
    global_tmp = Path(tempfile.gettempdir())
    before = {p.name for p in global_tmp.glob("pytest-of-*")}
    proc = _run_nested_bare_pytest(tmp_path / "sandbox")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 passed" in proc.stdout
    after = {p.name for p in global_tmp.glob("pytest-of-*")}
    assert after == before, f"bare pytest created new factory dirs: {after - before}"
    assert any(global_tmp.glob("sr-pytest-*")), "expected the pinned scratch dir"
