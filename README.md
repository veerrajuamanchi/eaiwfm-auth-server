# eaiwfm-auth-server
FastAPI/MSAL auth server

## Configuration sources (env/YAML/Key Vault)

The auth server resolves required settings in this order:

1) Environment variable (e.g. `AUTH_CLIENT_ID`)
2) `configs/auth.yaml` (intended for documentation/local defaults)
3) Azure Key Vault secret (hyphenated name, e.g. `AUTH-CLIENT-ID`)

### Key Vault selection

- Default vault (if not specified): `eaiwfm-prod-kv`
- To use a different vault (e.g. local dev): set `EAIWFM_KEYVAULT_NAME=eaiwfm-dev-kv`
- Optional: set `EAIWFM_KEYVAULT_URL=https://<vault>.vault.azure.net` to override URL directly
- Optional: disable Key Vault lookup entirely with `EAIWFM_KEYVAULT_ENABLED=0`

### Local authentication

For local runs on your machine, `DefaultAzureCredential` will use your Azure CLI login.

- `az login`
- `az account set --subscription "<your subscription>"`

