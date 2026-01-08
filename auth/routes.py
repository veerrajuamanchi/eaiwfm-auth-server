from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from auth.msal_client import build_authorization_url, create_confidential_client, exchange_code_for_tokens, new_flow_state
from auth.utils import AuthConfig, extract_user, load_auth_config, validate_id_token


router = APIRouter()


def get_auth_config() -> AuthConfig:
    return load_auth_config()


def _get_next(request: Request) -> str:
    nxt = request.query_params.get("next")
    if nxt and len(nxt) < 2000:
        return str(nxt)
    return "/"


@router.get("/login")
def login(request: Request, cfg: AuthConfig = Depends(get_auth_config)) -> RedirectResponse:
    app = create_confidential_client(cfg)
    flow = new_flow_state()

    request.session["oauth_state"] = flow.state
    request.session["oauth_nonce"] = flow.nonce
    request.session["next"] = _get_next(request)

    auth_url = build_authorization_url(app=app, cfg=cfg, flow=flow)
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/auth/callback")
def auth_callback(request: Request, cfg: AuthConfig = Depends(get_auth_config)) -> RedirectResponse:
    error = request.query_params.get("error")
    if error:
        desc = request.query_params.get("error_description") or "Authentication failed"
        raise HTTPException(status_code=401, detail=str(desc))

    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    expected_state = request.session.get("oauth_state")
    received_state = request.query_params.get("state")
    if not expected_state or not received_state or str(expected_state) != str(received_state):
        raise HTTPException(status_code=400, detail="Invalid state")

    app = create_confidential_client(cfg)
    token_result: dict[str, Any] = exchange_code_for_tokens(app=app, cfg=cfg, code=str(code))

    if "error" in token_result:
        msg = token_result.get("error_description") or token_result.get("error") or "Token exchange failed"
        raise HTTPException(status_code=401, detail=str(msg))

    id_token = token_result.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="Missing id_token in token response")

    nonce = request.session.get("oauth_nonce")
    claims = validate_id_token(
        str(id_token),
        authority_url=cfg.authority_url,
        audience=cfg.client_id,
        nonce=str(nonce) if nonce else None,
    )

    # Keep the session cookie small (Starlette stores session in a signed cookie).
    request.session["user"] = extract_user(claims)

    # Clear one-time flow values.
    request.session.pop("oauth_state", None)
    request.session.pop("oauth_nonce", None)

    nxt = request.session.get("next") or "/"
    request.session.pop("next", None)
    return RedirectResponse(url=str(nxt), status_code=302)


@router.get("/logout")
def logout(request: Request, cfg: AuthConfig = Depends(get_auth_config)) -> RedirectResponse:
    request.session.clear()

    end_session = f"{cfg.authority_url.rstrip('/')}/oauth2/v2.0/logout"
    params = urlencode({"post_logout_redirect_uri": cfg.post_logout_redirect_uri})
    return RedirectResponse(url=f"{end_session}?{params}", status_code=302)


@router.get("/api/me")
def me(request: Request) -> JSONResponse:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse(user)
