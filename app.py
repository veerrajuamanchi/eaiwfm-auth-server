from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from auth.routes import router
from auth.utils import load_auth_config


def create_app() -> FastAPI:
    cfg = load_auth_config()

    app = FastAPI(title="eaiwfm-auth-server")

    # Allow the frontend to call /api/me with cookies.
    cors_origins = [
        o.strip()
        for o in (os.getenv("AUTH_CORS_ORIGINS") or "http://localhost:3000").split(",")
        if o.strip()
    ]
    cors_origin_regex = os.getenv("AUTH_CORS_ORIGIN_REGEX") or r"^https?://(localhost|127\.0\.0\.1)(:\\d+)?$"

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_origin_regex=cors_origin_regex,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    app.add_middleware(
        SessionMiddleware,
        secret_key=cfg.session_secret,
        https_only=bool(cfg.cookie_secure),
        same_site=str(cfg.cookie_samesite),
        session_cookie="eaiwfm_session",
    )

    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app


app = create_app()
