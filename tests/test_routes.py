from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

import auth.routes as routes


def _make_client(monkeypatch):
    # Patch config and all MSAL/JWT-related calls inside routes module.
    cfg = routes.AuthConfig(
        tenant_id="tid",
        client_id="client",
        client_secret="secret",
        redirect_uri="http://localhost:8000/auth/callback",
        authority_url="https://login.microsoftonline.com/common",
        scopes=["email"],
        session_secret="sess",
        cookie_secure=False,
        cookie_samesite="lax",
        post_logout_redirect_uri="http://localhost:3000/",
    )

    monkeypatch.setattr(routes, "load_auth_config", lambda: cfg)

    # Satisfy app.py import-time config loading (app = create_app()).
    monkeypatch.setenv("AUTH_TENANT_ID", cfg.tenant_id)
    monkeypatch.setenv("AUTH_CLIENT_ID", cfg.client_id)
    monkeypatch.setenv("AUTH_CLIENT_SECRET", cfg.client_secret)
    monkeypatch.setenv("AUTH_SESSION_SECRET", cfg.session_secret)

    class FakeMsalApp:
        pass

    monkeypatch.setattr(routes, "create_confidential_client", lambda cfg: FakeMsalApp())
    monkeypatch.setattr(routes, "new_flow_state", lambda: type("F", (), {"state": "st", "nonce": "no"})())
    monkeypatch.setattr(routes, "build_authorization_url", lambda **kwargs: "https://login")

    import sys

    sys.modules.pop("app", None)
    import app as app_module

    client = TestClient(app_module.create_app())
    return client


def test_get_next_limits() -> None:
    class Req:
        def __init__(self, nxt):
            self.query_params = {"next": nxt}

    assert routes._get_next(Req("/x")) == "/x"
    assert routes._get_next(Req("x" * 3000)) == "/"


def test_login_sets_session_and_redirects(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/login?next=/dashboard", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "https://login"


def test_auth_callback_error_renders_no_access(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get(
        "/auth/callback?error=unauthorized_client&error_description=AADSTS50020%20tenant%20mismatch",
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert "Access Not Enabled" in r.text


def test_auth_callback_missing_code(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/auth/callback", follow_redirects=False)
    assert r.status_code == 400


def test_auth_callback_invalid_state(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/auth/callback?code=c&state=bad", follow_redirects=False)
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid state"


def test_auth_callback_token_exchange_error(monkeypatch) -> None:
    client = _make_client(monkeypatch)

    monkeypatch.setattr(
        routes,
        "exchange_code_for_tokens",
        lambda **kwargs: {"error": "bad", "error_description": "nope"},
    )

    # seed session state via /login
    client.get("/login", follow_redirects=False)
    r = client.get("/auth/callback?code=c&state=st", follow_redirects=False)
    assert r.status_code == 401


def test_auth_callback_success_sets_user_and_redirects(monkeypatch) -> None:
    client = _make_client(monkeypatch)

    monkeypatch.setattr(routes, "exchange_code_for_tokens", lambda **kwargs: {"id_token": "t"})
    monkeypatch.setattr(routes, "validate_id_token", lambda *a, **k: {"name": "Jane", "preferred_username": "jane@ex"})
    monkeypatch.setattr(routes, "extract_user", lambda claims: {"name": "Jane"})

    client.get("/login?next=/after", follow_redirects=False)
    r = client.get("/auth/callback?code=c&state=st", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/after"

    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["name"] == "Jane"


def test_api_me_unauthenticated(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/api/me")
    assert r.status_code == 401


def test_logout_clears_session_and_redirects(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    client.get("/login", follow_redirects=False)

    r = client.get("/logout", follow_redirects=False)
    assert r.status_code == 302
    assert "logout" in r.headers["location"]


def test_healthz(monkeypatch) -> None:
    client = _make_client(monkeypatch)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
