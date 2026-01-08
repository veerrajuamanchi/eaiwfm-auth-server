# eaiwfm-auth-server

Standalone auth server for eaiwfm using **Microsoft Entra ID (Azure AD)** via **MSAL for Python**.

It provides:
- `GET /login?next=<url>` – starts Entra sign-in
- `GET /auth/callback` – OAuth2/OIDC callback
- `GET /logout` – clears session and redirects to Entra logout
- `GET /api/me` – returns the signed-in user (cookie session)
- `GET /healthz` – health check

## Local development

1. Create a virtualenv and install deps:

```bash
cd eaiwfm-auth-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Create `.env` from `.env.example` and fill values.

3. Run the server:

```bash
uvicorn --env-file .env app:app --reload --host 0.0.0.0 --port 8000
```

## Frontend integration

In your React frontend, set:
- `REACT_APP_AUTH_BASE_URL=http://localhost:8000` (local)
- `REACT_APP_AUTH_BASE_URL=https://<your-auth-service-domain>` (Render)

This ensures the frontend redirects to the auth service (not the static site) for `/login` and `/logout`.

## Render deployment

Create a **Web Service** on Render pointing at this repo.

- Start command:
  - `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Environment:
  - `AUTH_TENANT_ID`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`
  - `AUTH_REDIRECT_URI=https://<your-auth-service-domain>/auth/callback`
  - `AUTH_SESSION_SECRET=<long random>`
  - `AUTH_COOKIE_SECURE=true`
  - `AUTH_COOKIE_SAMESITE=lax`
  - `AUTH_POST_LOGOUT_REDIRECT_URI=https://eaiwfm.com/`
  - `AUTH_CORS_ORIGINS=https://eaiwfm.com`

Microsoft Entra App Registration must include the same redirect URI:
- `https://<your-auth-service-domain>/auth/callback`
