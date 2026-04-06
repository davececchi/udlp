"""
Group Assignment Service — Databricks App

A privilege boundary service that assigns Entra ID / account-level groups
to Databricks workspaces via the Account API. Intended to be called by
CI/CD pipelines so they don't need account-admin credentials themselves.
"""

import os
import re
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import aiohttp
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("group-assignment-service")

# ---------------------------------------------------------------------------
# Configuration (populated at startup)
# ---------------------------------------------------------------------------
ACCOUNT_ID: str = ""
ACCOUNT_HOST: str = ""            # e.g. https://accounts.azuredatabricks.net
CLIENT_ID: str = ""               # account-admin service principal
CLIENT_SECRET: str = ""           # account-admin service principal secret
ALLOWED_WORKSPACES: set[str] = set()
ALLOWED_GROUP_PATTERN: Optional[re.Pattern] = None

# ---------------------------------------------------------------------------
# Lifespan — load config once
# ---------------------------------------------------------------------------

def _load_config() -> None:
    global ACCOUNT_ID, ACCOUNT_HOST, CLIENT_ID, CLIENT_SECRET
    global ALLOWED_WORKSPACES, ALLOWED_GROUP_PATTERN

    ACCOUNT_ID = os.environ.get("DATABRICKS_ACCOUNT_ID", "")
    ACCOUNT_HOST = os.environ.get("DATABRICKS_ACCOUNT_HOST", "").rstrip("/")
    CLIENT_ID = os.environ.get("ACCOUNT_SP_CLIENT_ID", "")
    CLIENT_SECRET = os.environ.get("ACCOUNT_SP_CLIENT_SECRET", "")

    if not all([ACCOUNT_ID, ACCOUNT_HOST, CLIENT_ID, CLIENT_SECRET]):
        log.warning(
            "Missing one or more required env vars: "
            "DATABRICKS_ACCOUNT_ID, DATABRICKS_ACCOUNT_HOST, "
            "ACCOUNT_SP_CLIENT_ID, ACCOUNT_SP_CLIENT_SECRET"
        )

    ws_raw = os.environ.get("ALLOWED_WORKSPACES", "").strip()
    if ws_raw:
        ALLOWED_WORKSPACES.update(w.strip() for w in ws_raw.split(",") if w.strip())
        log.info("Workspace allowlist: %s", ALLOWED_WORKSPACES)
    else:
        log.info("No workspace allowlist configured — all workspaces allowed.")

    gp_raw = os.environ.get("ALLOWED_GROUP_PATTERN", "").strip()
    if gp_raw:
        ALLOWED_GROUP_PATTERN = re.compile(gp_raw)
        log.info("Group name pattern: %s", gp_raw)
    else:
        log.info("No group name pattern configured — all groups allowed.")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_config()
    yield


app = FastAPI(
    title="Group Assignment Service",
    description="Assign Entra ID / account-level groups to Databricks workspaces.",
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Auth — get an OAuth token for the account-admin service principal
# ---------------------------------------------------------------------------
_token_cache: dict = {"token": None, "expires_at": 0.0}


async def _get_account_token() -> str:
    """Obtain an OAuth token from the Databricks accounts OIDC endpoint."""
    now = datetime.now(timezone.utc).timestamp()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]

    token_url = f"{ACCOUNT_HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "all-apis",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=payload) as resp:
            if resp.status != 200:
                body = await resp.text()
                log.error("Token request failed (%s): %s", resp.status, body)
                raise HTTPException(502, f"Failed to obtain account token: {body}")
            data = await resp.json()

    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 3600)
    log.info("Refreshed account-admin OAuth token.")
    return _token_cache["token"]


# ---------------------------------------------------------------------------
# Caller authentication — verify the caller is authenticated via the
# Databricks Apps built-in auth (forwarded access token).
# ---------------------------------------------------------------------------

async def verify_caller(request: Request) -> str:
    """
    Extract the caller identity from the Databricks-forwarded headers.
    In a Databricks App, authenticated users/SPs get a forwarded access
    token. We require its presence as proof the caller is authorized.
    Returns the caller identity string for audit logging.
    """
    # Databricks Apps forward the caller's token in this header
    token = request.headers.get("x-forwarded-access-token")
    if not token:
        # Also accept a standard Bearer token for local testing
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(401, "Missing authentication token.")
        token = auth_header.removeprefix("Bearer ")

    # The forwarded email/user header (set by Databricks Apps proxy)
    caller = (
        request.headers.get("x-forwarded-email")
        or request.headers.get("x-forwarded-user")
        or "unknown-caller"
    )
    return caller


# ---------------------------------------------------------------------------
# Policy enforcement helpers
# ---------------------------------------------------------------------------

def _check_workspace_allowed(workspace_id: str) -> None:
    if ALLOWED_WORKSPACES and workspace_id not in ALLOWED_WORKSPACES:
        raise HTTPException(
            403,
            f"Workspace {workspace_id} is not in the allowlist.",
        )


def _check_group_name_allowed(group_display_name: str) -> None:
    if ALLOWED_GROUP_PATTERN and not ALLOWED_GROUP_PATTERN.search(group_display_name):
        raise HTTPException(
            403,
            f"Group name '{group_display_name}' does not match the allowed pattern.",
        )


# ---------------------------------------------------------------------------
# Account API helpers
# ---------------------------------------------------------------------------

async def _account_api(
    method: str,
    path: str,
    json_body: Optional[dict] = None,
) -> tuple[int, dict | list | str]:
    """Call the Databricks Account API and return (status, body)."""
    token = await _get_account_token()
    url = f"{ACCOUNT_HOST}/api/2.0/accounts/{ACCOUNT_ID}{path}"
    headers = {"Authorization": f"Bearer {token}"}

    async with aiohttp.ClientSession() as session:
        async with session.request(
            method, url, headers=headers, json=json_body
        ) as resp:
            status = resp.status
            try:
                body = await resp.json()
            except Exception:
                body = await resp.text()
            return status, body


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AssignGroupRequest(BaseModel):
    """Body for PUT — assign a group to a workspace."""
    permissions: list[str] = Field(
        default=["USER"],
        description='Permission level(s) to grant. Valid values: "USER", "ADMIN".',
    )


class AssignmentInfo(BaseModel):
    principal_id: int
    permissions: list[str]


class ListAssignmentsResponse(BaseModel):
    permission_assignments: list[AssignmentInfo]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    configured = all([ACCOUNT_ID, ACCOUNT_HOST, CLIENT_ID, CLIENT_SECRET])
    return {
        "status": "healthy",
        "configured": configured,
        "allowed_workspaces": sorted(ALLOWED_WORKSPACES) if ALLOWED_WORKSPACES else "all",
        "allowed_group_pattern": ALLOWED_GROUP_PATTERN.pattern if ALLOWED_GROUP_PATTERN else "all",
    }


@app.put("/api/workspaces/{workspace_id}/groups/{group_id}")
async def assign_group(
    workspace_id: str,
    group_id: str,
    body: AssignGroupRequest = AssignGroupRequest(),
    caller: str = Depends(verify_caller),
):
    """Assign an account-level group to a workspace."""
    _check_workspace_allowed(workspace_id)

    # Validate permission values
    valid_permissions = {"USER", "ADMIN"}
    for p in body.permissions:
        if p not in valid_permissions:
            raise HTTPException(400, f"Invalid permission '{p}'. Must be one of {valid_permissions}.")

    log.info(
        "ASSIGN | caller=%s workspace=%s group=%s permissions=%s",
        caller, workspace_id, group_id, body.permissions,
    )

    status, resp_body = await _account_api(
        "PUT",
        f"/workspaces/{workspace_id}/permissionassignments/principals/{group_id}",
        json_body={"permissions": body.permissions},
    )

    if status >= 400:
        log.error(
            "ASSIGN FAILED | workspace=%s group=%s status=%s body=%s",
            workspace_id, group_id, status, resp_body,
        )
        raise HTTPException(status, detail=resp_body)

    log.info(
        "ASSIGN OK | workspace=%s group=%s permissions=%s",
        workspace_id, group_id, body.permissions,
    )
    return {"status": "assigned", "workspace_id": workspace_id, "group_id": group_id, "permissions": body.permissions}


@app.delete("/api/workspaces/{workspace_id}/groups/{group_id}")
async def remove_group(
    workspace_id: str,
    group_id: str,
    caller: str = Depends(verify_caller),
):
    """Remove a group assignment from a workspace."""
    _check_workspace_allowed(workspace_id)

    log.info(
        "REMOVE | caller=%s workspace=%s group=%s",
        caller, workspace_id, group_id,
    )

    status, resp_body = await _account_api(
        "DELETE",
        f"/workspaces/{workspace_id}/permissionassignments/principals/{group_id}",
    )

    if status >= 400:
        log.error(
            "REMOVE FAILED | workspace=%s group=%s status=%s body=%s",
            workspace_id, group_id, status, resp_body,
        )
        raise HTTPException(status, detail=resp_body)

    log.info("REMOVE OK | workspace=%s group=%s", workspace_id, group_id)
    return {"status": "removed", "workspace_id": workspace_id, "group_id": group_id}


@app.get("/api/workspaces/{workspace_id}/groups")
async def list_groups(
    workspace_id: str,
    caller: str = Depends(verify_caller),
):
    """List all group/principal permission assignments for a workspace."""
    _check_workspace_allowed(workspace_id)

    log.info("LIST | caller=%s workspace=%s", caller, workspace_id)

    status, resp_body = await _account_api(
        "GET",
        f"/workspaces/{workspace_id}/permissionassignments",
    )

    if status >= 400:
        log.error(
            "LIST FAILED | workspace=%s status=%s body=%s",
            workspace_id, status, resp_body,
        )
        raise HTTPException(status, detail=resp_body)

    return resp_body


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
