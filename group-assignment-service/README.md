# Group Assignment Service

A Databricks App that acts as a privilege boundary for assigning Entra ID / account-level groups to workspaces via the Databricks Account API. CI/CD pipelines call this app instead of holding account-admin credentials themselves.

## How it works

1. Groups are synced from Entra ID to the Databricks account via AIM (Automatic Identity Management).
2. This app exposes a simple REST API to assign those account-level groups to specific workspaces.
3. The app authenticates to the Account API using an account-admin service principal whose credentials are stored as Databricks secrets.
4. Callers are authenticated via the Databricks Apps built-in auth proxy (forwarded access tokens).

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `PUT` | `/api/workspaces/{workspace_id}/groups/{group_id}` | Assign a group to a workspace |
| `DELETE` | `/api/workspaces/{workspace_id}/groups/{group_id}` | Remove a group from a workspace |
| `GET` | `/api/workspaces/{workspace_id}/groups` | List all assignments for a workspace |
| `GET` | `/api/health` | Health check |

### Assign a group

```bash
curl -X PUT \
  "https://<app-url>/api/workspaces/1234567890/groups/9876543" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["USER"]}'
```

The `permissions` field accepts `["USER"]` (default) or `["ADMIN"]`.

### Remove a group

```bash
curl -X DELETE \
  "https://<app-url>/api/workspaces/1234567890/groups/9876543" \
  -H "Authorization: Bearer $TOKEN"
```

### List assignments

```bash
curl "https://<app-url>/api/workspaces/1234567890/groups" \
  -H "Authorization: Bearer $TOKEN"
```

## Configuration

### Required environment variables

| Variable | Source | Description |
|----------|--------|-------------|
| `DATABRICKS_ACCOUNT_ID` | Static value in `app.yaml` | Your Databricks account ID |
| `DATABRICKS_ACCOUNT_HOST` | Static value in `app.yaml` | Account console URL (e.g., `https://accounts.azuredatabricks.net`) |
| `ACCOUNT_SP_CLIENT_ID` | Databricks secret resource | Client ID of the account-admin service principal |
| `ACCOUNT_SP_CLIENT_SECRET` | Databricks secret resource | Client secret of the account-admin service principal |

### Optional policy variables

| Variable | Description |
|----------|-------------|
| `ALLOWED_WORKSPACES` | Comma-separated list of workspace IDs. If set, only these workspaces can be targeted. |
| `ALLOWED_GROUP_PATTERN` | Regex pattern for allowed group display names. If set, group names must match. |

## Deployment

### 1. Create the app

```bash
databricks apps create group-assignment-service \
  --description "Privilege boundary for workspace group assignments" \
  --profile uhg-fevm
```

### 2. Sync and deploy

```bash
databricks sync . /Workspace/Users/<your-email>/group-assignment-service --profile uhg-fevm

databricks apps deploy group-assignment-service \
  --source-code-path /Workspace/Users/<your-email>/group-assignment-service \
  --profile uhg-fevm
```

### 3. Add secret resources in the UI

1. Go to **Compute > Apps > group-assignment-service > Edit**
2. Add resource: **Secret** with key `account-sp-client-id` -> the SP's client ID
3. Add resource: **Secret** with key `account-sp-secret` -> the SP's client secret
4. Set `DATABRICKS_ACCOUNT_ID` in the app.yaml to your actual account ID

### 4. Redeploy to pick up resources

```bash
databricks apps deploy group-assignment-service \
  --source-code-path /Workspace/Users/<your-email>/group-assignment-service \
  --profile uhg-fevm
```

## Local development

```bash
# Create a virtual environment
python -m venv .venv && source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABRICKS_ACCOUNT_ID="your-account-id"
export DATABRICKS_ACCOUNT_HOST="https://accounts.azuredatabricks.net"
export ACCOUNT_SP_CLIENT_ID="your-sp-client-id"
export ACCOUNT_SP_CLIENT_SECRET="your-sp-client-secret"
export PORT=8000

# Run
python app.py
```

The service will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.
