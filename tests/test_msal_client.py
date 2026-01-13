from __future__ import annotations

import auth.msal_client as mc


def test_new_flow_state_deterministic(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_token_urlsafe(n):
        calls["n"] += 1
        return f"tok{calls['n']}"

    monkeypatch.setattr(mc.secrets, "token_urlsafe", fake_token_urlsafe)

    flow = mc.new_flow_state()
    assert flow.state == "tok1"
    assert flow.nonce == "tok2"


def test_build_authorization_url_passes_params() -> None:
    class FakeApp:
        def __init__(self):
            self.kw = None

        def get_authorization_request_url(self, **kwargs):
            self.kw = kwargs
            return "https://example/auth"

    cfg = type(
        "Cfg",
        (),
        {"scopes": ["email"], "redirect_uri": "http://localhost/cb"},
    )

    app = FakeApp()
    flow = mc.AuthFlowState(state="s", nonce="n")
    url = mc.build_authorization_url(app=app, cfg=cfg, flow=flow)

    assert url == "https://example/auth"
    assert app.kw["state"] == "s"
    assert app.kw["nonce"] == "n"
    assert app.kw["scopes"] == ["email"]


def test_exchange_code_for_tokens_calls_msal() -> None:
    class FakeApp:
        def __init__(self):
            self.kw = None

        def acquire_token_by_authorization_code(self, **kwargs):
            self.kw = kwargs
            return {"id_token": "t"}

    cfg = type("Cfg", (), {"scopes": ["email"], "redirect_uri": "http://localhost/cb"})
    app = FakeApp()

    out = mc.exchange_code_for_tokens(app=app, cfg=cfg, code="c")
    assert out["id_token"] == "t"
    assert app.kw["code"] == "c"


def test_create_confidential_client_constructs_msal_app(monkeypatch) -> None:
    calls = {}

    class FakeCCA:
        def __init__(self, client_id, authority, client_credential):
            calls["client_id"] = client_id
            calls["authority"] = authority
            calls["client_credential"] = client_credential

    monkeypatch.setattr(mc.msal, "ConfidentialClientApplication", FakeCCA)

    cfg = type(
        "Cfg",
        (),
        {"client_id": "cid", "authority_url": "https://login/tenant", "client_secret": "sec"},
    )

    app = mc.create_confidential_client(cfg)
    assert isinstance(app, FakeCCA)
    assert calls["client_id"] == "cid"
