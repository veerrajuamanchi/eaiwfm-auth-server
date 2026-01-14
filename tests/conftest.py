from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_keyvault_by_default(monkeypatch):
    """Keep unit tests deterministic by preventing real Key Vault lookups."""
    monkeypatch.setenv("EAIWFM_KEYVAULT_ENABLED", "0")
    yield
