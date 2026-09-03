"""
ThreatGate - SCM OAuth2 Client
SCM OAuth2 認證模組

Gets, caches and refreshes the access token used to call Palo Alto Networks'
Strata Cloud Manager (SCM) API. This is the "real" production adapter - it
talks to the actual public SCM endpoint, but every credential comes from
environment variables. Nothing here is usable without your own SCM tenant
and service account, which is exactly the point: safe to publish as-is.

- OAuth 2.0 Client Credentials Grant (machine-to-machine, no human login/MFA)
- Access token is cached in memory and refreshed ~5 minutes before expiry

Required environment variables:
- SCM_CLIENT_ID
- SCM_CLIENT_SECRET
- SCM_TSG_ID   (Tenant Service Group ID)
"""

import os
import time

import requests

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
TIMEOUT = 15
EXPIRY_BUFFER_SECONDS = 300  # refresh 5 minutes before expiry

_token_cache = {"access_token": None, "expires_at": 0}


def _request_new_token():
    client_id = os.environ.get("SCM_CLIENT_ID")
    client_secret = os.environ.get("SCM_CLIENT_SECRET")
    tsg_id = os.environ.get("SCM_TSG_ID")

    missing = [name for name, val in [
        ("SCM_CLIENT_ID", client_id),
        ("SCM_CLIENT_SECRET", client_secret),
        ("SCM_TSG_ID", tsg_id),
    ] if not val]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tsg_id}",
    }
    resp = requests.post(
        TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    if "access_token" not in data:
        raise RuntimeError(f"SCM auth response has no access_token: {data}")

    return data["access_token"], data.get("expires_in", 900)


def get_access_token(force_refresh=False):
    now = time.time()
    if not force_refresh and _token_cache["access_token"] and now < _token_cache["expires_at"]:
        return _token_cache["access_token"]

    access_token, expires_in = _request_new_token()
    _token_cache["access_token"] = access_token
    _token_cache["expires_at"] = now + expires_in - EXPIRY_BUFFER_SECONDS
    return access_token


def get_auth_header(force_refresh=False):
    token = get_access_token(force_refresh=force_refresh)
    return {"Authorization": f"Bearer {token}"}


if __name__ == "__main__":
    try:
        token = get_access_token()
        remaining = int(_token_cache["expires_at"] - time.time())
        print("Token acquired successfully")
        print(f"First 12 chars (for verification only): {token[:12]}...")
        print(f"Refreshes again in ~{remaining}s")
    except Exception as e:
        print(f"Failed to get token: {e}")
