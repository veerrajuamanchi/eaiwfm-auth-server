from __future__ import annotations

import importlib

import pytest

import auth.utils as utils


def test_env_required_and_placeholder(monkeypatch) -> None:
    monkeypatch.delenv("X", raising=False)
    with pytest.raises(RuntimeError, match=r"Missing required environment variable: X"):
        utils._env("X", required=True)

    monkeypatch.setenv("X", "<TEMPLATE>")
    with pytest.raises(RuntimeError, match=r"template placeholder"):
        utils._env("X", required=True)

    monkeypatch.setenv("X", " value ")
    assert utils._env("X", required=True) == "value"


def test_parse_bool() -> None:
    assert utils._parse_bool("1") is True
    assert utils._parse_bool("true") is True
    assert utils._parse_bool("yes") is True
    assert utils._parse_bool("0") is False
    assert utils._parse_bool("false") is False
    assert utils._parse_bool("no") is False
    assert utils._parse_bool("maybe", default=True) is True


def test_load_auth_config_yaml_and_env_override(monkeypatch, tmp_path) -> None:
    cfg_path = tmp_path / "auth.yaml"
    cfg_path.write_text(
        (
            "tenant_id: tid\n"
            "client_id: cid\n"
            "client_secret: secret\n"
            "redirect_uri: http://localhost:8000/auth/callback\n"
            "session_secret: sess\n"
            "cookie_secure: false\n"
            "cookie_samesite: lax\n"
            "post_logout_redirect_uri: http://localhost:3000/\n"
            "scopes: [openid, profile, email, offline_access]\n"
        ),
        encoding="utf-8",
    )

    # required can come from yaml
    monkeypatch.delenv("AUTH_TENANT_ID", raising=False)
    monkeypatch.delenv("AUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)

    cfg = utils.load_auth_config(str(cfg_path))
    assert cfg.tenant_id == "tid"
    assert cfg.authority_url.endswith("/tid")
    # reserved scopes should be filtered leaving email
    assert cfg.scopes == ["email"]

    # env override for scopes
    monkeypatch.setenv("AUTH_TENANT_ID", "tid")
    monkeypatch.setenv("AUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("AUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AUTH_SESSION_SECRET", "sess")
    monkeypatch.setenv("AUTH_SCOPES", "email, api://x/.default openid")

    cfg2 = utils.load_auth_config(str(cfg_path))
    assert "openid" not in cfg2.scopes
    assert cfg2.scopes == ["email", "api://x/.default"]


def test_get_jwks_caches(monkeypatch) -> None:
    utils._JWKS_CACHE.clear()

    calls = {"n": 0}

    class Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"keys": [{"kid": "k1"}]}

    def fake_get(url, timeout):
        calls["n"] += 1
        return Resp()

    monkeypatch.setattr(utils.requests, "get", fake_get)

    first = utils.get_jwks("https://login.microsoftonline.com/tid", ttl_seconds=3600)
    second = utils.get_jwks("https://login.microsoftonline.com/tid", ttl_seconds=3600)
    assert first == second
    assert calls["n"] == 1


def test_validate_id_token_multi_tenant_and_nonce(monkeypatch) -> None:
    # Make validate_id_token deterministic by stubbing jwt functions.
    utils._JWKS_CACHE.clear()

    monkeypatch.setattr(utils, "get_jwks", lambda authority_url: {"keys": [{"kid": "kid1"}]})
    monkeypatch.setattr(utils.jwt, "get_unverified_header", lambda token: {"kid": "kid1"})

    class FakeRSA:
        @staticmethod
        def from_jwk(jwk):
            return "PUBLICKEY"

    monkeypatch.setattr(utils.jwt.algorithms, "RSAAlgorithm", FakeRSA)

    def fake_decode(token, key, algorithms, audience, options):
        assert audience == "client"
        return {
            "iss": "https://login.microsoftonline.com/tenant123/v2.0",
            "tid": "tenant123",
            "aud": "client",
            "exp": 9999999999,
            "iat": 1,
            "nonce": "n",
            "name": "Jane",
            "preferred_username": "jane@example.com",
        }

    monkeypatch.setattr(utils.jwt, "decode", fake_decode)

    # authority common triggers tid-required + issuer recompute
    monkeypatch.delenv("AUTH_ALLOWED_TENANTS", raising=False)
    claims = utils.validate_id_token(
        "token",
        authority_url="https://login.microsoftonline.com/common",
        audience="client",
        nonce="n",
    )
    assert claims["tid"] == "tenant123"

    with pytest.raises(ValueError, match=r"Invalid nonce"):
        utils.validate_id_token(
            "token",
            authority_url="https://login.microsoftonline.com/common",
            audience="client",
            nonce="wrong",
        )


def test_validate_id_token_missing_kid_or_key(monkeypatch) -> None:
    monkeypatch.setattr(utils, "get_jwks", lambda authority_url: {"keys": []})
    monkeypatch.setattr(utils.jwt, "get_unverified_header", lambda token: {})

    with pytest.raises(ValueError, match=r"Missing kid"):
        utils.validate_id_token(
            "token",
            authority_url="https://login.microsoftonline.com/tid",
            audience="client",
            nonce=None,
        )

    monkeypatch.setattr(utils.jwt, "get_unverified_header", lambda token: {"kid": "k"})
    with pytest.raises(ValueError, match=r"Unable to find signing key"):
        utils.validate_id_token(
            "token",
            authority_url="https://login.microsoftonline.com/tid",
            audience="client",
            nonce=None,
        )


def test_validate_id_token_allowed_tenants(monkeypatch) -> None:
    utils._JWKS_CACHE.clear()
    monkeypatch.setattr(utils, "get_jwks", lambda authority_url: {"keys": [{"kid": "kid1"}]})
    monkeypatch.setattr(utils.jwt, "get_unverified_header", lambda token: {"kid": "kid1"})

    class FakeRSA:
        @staticmethod
        def from_jwk(jwk):
            return "PUBLICKEY"

    monkeypatch.setattr(utils.jwt.algorithms, "RSAAlgorithm", FakeRSA)

    monkeypatch.setattr(
        utils.jwt,
        "decode",
        lambda *args, **kwargs: {
            "iss": "https://login.microsoftonline.com/tenantX/v2.0",
            "tid": "tenantX",
            "aud": "client",
            "exp": 9999999999,
            "iat": 1,
        },
    )

    monkeypatch.setenv("AUTH_ALLOWED_TENANTS", "tenantY")
    with pytest.raises(ValueError, match=r"Tenant not allowed"):
        utils.validate_id_token(
            "token",
            authority_url="https://login.microsoftonline.com/organizations",
            audience="client",
            nonce=None,
        )


def test_extract_user_helpers() -> None:
    claims = {
        "name": ["Jane"],
        "upn": "jane@ex",
        "oid": "oid",
        "tid": "tid",
        "roles": ["r1", ""],
        "groups": ["g1"],
    }
    user = utils.extract_user(claims)
    assert user["name"] == "Jane"
    assert user["preferred_username"] == "jane@ex"
    assert user["roles"] == ["r1"]
    assert user["groups"] == ["g1"]
