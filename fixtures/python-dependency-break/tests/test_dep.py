def test_always():
    # The locked patched pytest baseline passes.
    # When dependencies=latest-allowed, our install script may install a marker file.
    import os
    if os.environ.get("TOMORROWCI_FORCE_DEP_FAIL") == "1":
        raise RuntimeError("simulated dependency API break")
    assert True
