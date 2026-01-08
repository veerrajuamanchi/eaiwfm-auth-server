from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import jwt
import requests
import yaml


@dataclass(frozen=True)
class AuthConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authority_url: str
    scopes: list[str]
    session_secret: str
    cookie_secure: bool
    cookie_samesite: str
    post_logout_redirect_uri: str


def _env(name: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.getenv(name)
    chosen = (str(v).strip() if v is not None else "")
    if not chosen:
        chosen = (str(default).strip() if default is not None else "")

    if required:
        if not chosen:
            raise RuntimeError(f"Missing required environment variable: {name}")
        if chosen.startswith("<") and chosen.endswith(">"):
            raise RuntimeError(f"Missing required environment variable: {name} (template placeholder)")

    return chosen


def _parse_bool(v: str, default: bool = False) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def load_auth_config(config_path: str = "configs/auth.yaml") -> AuthConfig:
    repo_root = Path(__file__).resolve().parents[1]
    resolved_path = Path(config_path)
    if not resolved_path.is_absolute():
        resolved_path = repo_root / resolved_path

    data: dict[str, Any] = {}
    if resolved_path.exists():
        with open(resolved_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    tenant_id = _env("AUTH_TENANT_ID", str(data.get("tenant_id") or ""), required=True)
    client_id = _env("AUTH_CLIENT_ID", str(data.get("client_id") or ""), required=True)
    client_secret = _env("AUTH_CLIENT_SECRET", str(data.get("client_secret") or ""), required=True)
    redirect_uri = _env(
        "AUTH_REDIRECT_URI",
        str(data.get("redirect_uri") or "http://localhost:8000/auth/callback"),
        required=True,
    )

    default_authority = f"https://login.microsoftonline.com/{tenant_id}"

    yaml_authority = str(data.get("authority_url") or "").strip()
    if not yaml_authority or "<" in yaml_authority or ">" in yaml_authority:
        yaml_authority = ""

    authority_url = _env("AUTH_AUTHORITY_URL", yaml_authority or default_authority)

    scopes = os.getenv("AUTH_SCOPES")
    if scopes:
        scopes_list = [s.strip() for s in scopes.replace(",", " ").split() if s.strip()]
    else:
        scopes_list = [str(s).strip() for s in (data.get("scopes") or ["openid", "profile", "email"]) if str(s).strip()]

    reserved = {"openid", "profile", "offline_access"}
    scopes_list = [s for s in scopes_list if s not in reserved]
    if not scopes_list:
        scopes_list = ["email"]

    session_secret = _env("AUTH_SESSION_SECRET", str(data.get("session_secret") or ""), required=True)

    cookie_secure = _parse_bool(_env("AUTH_COOKIE_SECURE", str(data.get("cookie_secure") or "false")))
    cookie_samesite = _env("AUTH_COOKIE_SAMESITE", str(data.get("cookie_samesite") or "lax"))

    post_logout_redirect_uri = _env(
        "AUTH_POST_LOGOUT_REDIRECT_URI",
        str(data.get("post_logout_redirect_uri") or "http://localhost:3000/"),
    )

    return AuthConfig(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        authority_url=authority_url,
        scopes=scopes_list,
        session_secret=session_secret,
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite,
        post_logout_redirect_uri=post_logout_redirect_uri,
    )


_JWKS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _jwks_url(authority_url: str) -> str:
    base = authority_url.rstrip("/")
    return f"{base}/discovery/v2.0/keys"


def get_jwks(authority_url: str, *, ttl_seconds: int = 3600) -> dict[str, Any]:
    now = time.time()
    cached = _JWKS_CACHE.get(authority_url)
    if cached and (now - cached[0]) < ttl_seconds:
        return cached[1]

    resp = requests.get(_jwks_url(authority_url), timeout=10)
    resp.raise_for_status()
    jwks = resp.json()
    _JWKS_CACHE[authority_url] = (now, jwks)
    return jwks


def _first(values: Any) -> str | None:
    if values is None:
        return None
    if isinstance(values, str):
        return values
    if isinstance(values, Iterable):
        for v in values:
            if v:
                return str(v)
    return None


def validate_id_token(
    id_token: str,
    *,
    authority_url: str,
    audience: str,
    nonce: str | None,
) -> dict[str, Any]:
    jwks = get_jwks(authority_url)
    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header.get("kid")
    if not kid:
        raise ValueError("Missing kid in token header")

    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            key = k
            break
    if not key:
        raise ValueError("Unable to find signing key for token")

    authority_base = authority_url.rstrip("/")
    authority_tenant = authority_base.split("/")[-1].lower()

    claims = jwt.decode(
        id_token,
        key=jwt.algorithms.RSAAlgorithm.from_jwk(key),
        algorithms=["RS256"],
        audience=audience,
        options={"require": ["exp", "iat", "iss", "aud"]},
    )

    iss = claims.get("iss")
    if iss:
        iss_str = str(iss)
        if authority_tenant in {"common", "organizations", "consumers"}:
            tid = claims.get("tid")
            if not tid:
                raise ValueError("Missing tid for multi-tenant token")

            allowed = os.getenv("AUTH_ALLOWED_TENANTS")
            if allowed:
                allowed_set = {t.strip() for t in allowed.split(",") if t.strip()}
                if str(tid) not in allowed_set:
                    raise ValueError("Tenant not allowed")

            expected_issuer = f"https://login.microsoftonline.com/{tid}/v2.0"
        else:
            expected_issuer = f"{authority_base}/v2.0"

        if iss_str != expected_issuer:
            raise ValueError("Unexpected issuer")

    if nonce is not None:
        token_nonce = claims.get("nonce")
        if not token_nonce or str(token_nonce) != str(nonce):
            raise ValueError("Invalid nonce")

    return claims


def extract_roles(claims: dict[str, Any]) -> list[str]:
    roles = claims.get("roles")
    if isinstance(roles, list):
        return [str(r) for r in roles if r]
    return []


def extract_groups(claims: dict[str, Any]) -> list[str]:
    groups = claims.get("groups")
    if isinstance(groups, list):
        return [str(g) for g in groups if g]
    return []


def extract_user(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": _first(claims.get("name")),
        "preferred_username": _first(claims.get("preferred_username")) or _first(claims.get("upn")),
        "oid": _first(claims.get("oid")),
        "tid": _first(claims.get("tid")),
        "roles": extract_roles(claims),
        "groups": extract_groups(claims),
    }
