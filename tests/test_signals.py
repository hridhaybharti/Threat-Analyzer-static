"""Legacy tests for the previous backend.engine implementation.

The project has been refactored into backend/analyzers + backend/heuristics.
New tests live in tests/test_* (validators/scorer/heuristics/persistence).
"""

import pytest

pytest.skip("Legacy engine tests removed after refactor", allow_module_level=True)
