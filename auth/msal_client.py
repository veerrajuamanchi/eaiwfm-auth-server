from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass

import msal

from auth.utils import AuthConfig


@dataclass(frozen=True)
class AuthFlowState:
    state: str
    nonce: str


_log = logging.getLogger("eaiwfm.auth.msal")


def _debug_redirect_enabled() -> bool:
    return os.getenv("AUTH_DEBUG_REDIRECT_URI", "0").strip().lower() in {"1", "true", "yes", "y", "on"}


def create_confidential_client(cfg: AuthConfig) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=cfg.client_id,
        authority=cfg.authority_url,
        client_credential=cfg.client_secret,
    )


def new_flow_state() -> AuthFlowState:
    return AuthFlowState(state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32))


def build_authorization_url(
    *,
    app: msal.ConfidentialClientApplication,
    cfg: AuthConfig,
    flow: AuthFlowState,
) -> str:
    if _debug_redirect_enabled():
        _log.warning("MSAL get_authorization_request_url redirect_uri=%s", cfg.redirect_uri)
    return app.get_authorization_request_url(
        scopes=cfg.scopes,
        state=flow.state,
        redirect_uri=cfg.redirect_uri,
        response_mode="query",
        prompt=None,
        nonce=flow.nonce,
    )


def exchange_code_for_tokens(
    *,
    app: msal.ConfidentialClientApplication,
    cfg: AuthConfig,
    code: str,
) -> dict:
    if _debug_redirect_enabled():
        _log.warning("MSAL acquire_token_by_authorization_code redirect_uri=%s", cfg.redirect_uri)
    return app.acquire_token_by_authorization_code(
        code=code,
        scopes=cfg.scopes,
        redirect_uri=cfg.redirect_uri,
    )
