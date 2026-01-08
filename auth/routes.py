from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse, RedirectResponse

from auth.msal_client import build_authorization_url, create_confidential_client, exchange_code_for_tokens, new_flow_state
from auth.utils import AuthConfig, extract_user, load_auth_config, validate_id_token


router = APIRouter()


def _render_no_access_page(*, title: str, body_html: str, details: str | None = None) -> HTMLResponse:
        safe_title = (title or "Access Not Enabled for This Account").strip()
        safe_details = (details or "").strip()

        details_block = ""
        if safe_details:
                details_block = (
                        "<details style=\"margin-top:16px\">"
                        "<summary>Technical details</summary>"
                        f"<pre style=\"white-space:pre-wrap;word-break:break-word;\">{safe_details}</pre>"
                        "</details>"
                )

        html = f"""<!doctype html>
<html lang=\"en\">
    <head>
        <meta charset=\"utf-8\" />
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
        <title>{safe_title}</title>
    </head>
    <body style=\"font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;line-height:1.45\">
        <h1 style=\"margin:0 0 12px\">{safe_title}</h1>
        {body_html}
        {details_block}
    </body>
</html>"""
        return HTMLResponse(content=html, status_code=403)


def _render_access_not_enabled(*, details: str | None = None) -> HTMLResponse:
        return _render_no_access_page(
                title="Access Not Enabled for This Account",
                body_html=(
                        "<p style=\"margin:0 0 12px\">"
                        "Your organization is not currently authorized to access the Enterprise AI Agents Workforce Management platform."
                        "</p>"
                        "<p style=\"margin:0 0 16px\">"
                        "If you would like to request a demo or obtain access, please contact "
                        "<a href=\"mailto:founder@eaiwfm.com\">founder@eaiwfm.com</a>."
                        "</p>"
                ),
                details=details,
        )


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
        code_hint = f"{error} {desc}".strip()
        code_hint_lower = code_hint.lower()

        # Common "no access" / tenant mismatch cases.
        if (
            "aadsts50020" in code_hint_lower
            or "does not exist in tenant" in code_hint_lower
            or "unauthorized_client" in code_hint_lower
            or "not enabled for consumers" in code_hint_lower
        ):
            return _render_access_not_enabled(details=str(desc))

        return _render_no_access_page(
            title="Sign-in error",
            body_html=(
                "<p style=\"margin:0 0 12px\">Sorry, but we’re having trouble signing you in.</p>"
                "<p style=\"margin:0 0 16px\">If the problem persists, contact "
                "<a href=\"mailto:founder@eaiwfm.com\">founder@eaiwfm.com</a>."
                "</p>"
            ),
            details=str(desc),
        )

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


@router.get("/auth/no-access")
def no_access(message: str | None = None, details: str | None = None) -> HTMLResponse:
    # Backward-compatible endpoint; show the access-not-enabled page.
    # (The query parameter `message` is ignored now to keep UX consistent.)
    return _render_access_not_enabled(details=details)


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
