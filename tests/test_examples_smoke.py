"""Smoke test: every example in examples/ runs to completion under subprocess.

Catches the most common regression — public-API drift that breaks the
narrative the examples (and README) tell. Each example completes in a few
seconds against the in-process mock OIDC provider; if any errors out, this
test fails with the example's stderr in the assertion message.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = PROJECT_ROOT / "examples"
EXAMPLE_SCRIPTS = sorted(EXAMPLES_DIR.glob("*.py"))


@pytest.mark.parametrize("script", EXAMPLE_SCRIPTS, ids=lambda p: p.name)
def test_example_script_runs_to_completion(script: Path) -> None:
    """Run an example as a subprocess. Anything other than exit 0 fails."""
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"{script.name} exited {result.returncode}\n"
        f"STDOUT (tail):\n{result.stdout[-500:]}\n"
        f"STDERR (tail):\n{result.stderr[-500:]}"
    )
    # Every demo prints "Done." at the bottom — sanity check it actually ran end-to-end.
    assert "Done." in result.stdout, f"{script.name} did not print 'Done.' marker"
