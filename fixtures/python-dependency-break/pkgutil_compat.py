"""Uses a pytest version marker; the simulated candidate break is environment-driven."""

def version_gate():
    import pytest
    # The patched baseline exposes __version__.
    return hasattr(pytest, "__version__")
