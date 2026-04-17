#!/usr/bin/env bash
#
# install_cost_reporting_genie_azure.sh
#
# Installs the Databricks "Cost Reporting Genie" space into an Azure Databricks
# workspace using the Databricks CLI.
#
# Source repo:  https://github.com/numanali-db/Cost-Reporting-Genie
# CLI command:  databricks genie create-space
#
# Prerequisites
#   * Databricks CLI v0.205+ installed and on PATH
#       https://docs.databricks.com/aws/en/dev-tools/cli/install
#   * jq, curl
#   * A Databricks CLI profile already authenticated against the target Azure
#     workspace (run `databricks auth login --host https://adb-XXXX.NN.azuredatabricks.net`)
#   * The authenticated user must have:
#       - access to system.billing.* and system.access.workspaces_latest
#       - CAN_USE on at least one Pro or Serverless SQL Warehouse
#       - write access to the workspace folder used as parent_path
#
# Usage
#   ./install_cost_reporting_genie_azure.sh -p <profile>
#
#   -p, --profile <name>   (required) Databricks CLI profile to use. List your
#                          configured profiles with: databricks auth profiles
#
set -euo pipefail

GENIE_JSON_URL="https://raw.githubusercontent.com/numanali-db/Cost-Reporting-Genie/main/Azure_cost_reporting_genie_space_v2.0.json"
PROFILE=""
PARENT_PATH=""

usage() {
  sed -n '2,28p' "$0"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile)     PROFILE="$2"; shift 2 ;;
    --parent-path)    PARENT_PATH="$2"; shift 2 ;;
    -h|--help)        usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

for cmd in databricks jq curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required but not installed." >&2; exit 1; }
done

if [[ -z "$PROFILE" ]]; then
  echo "ERROR: --profile/-p is required." >&2
  echo >&2
  echo "List your configured profiles:" >&2
  echo "  databricks auth profiles" >&2
  echo >&2
  echo "Then re-run with: $0 -p <profile>" >&2
  exit 1
fi

DBX_FLAGS=(-p "$PROFILE")

# ---------------------------------------------------------------------------
# Step (a): Confirm the user is logged in and on the correct profile.
# ---------------------------------------------------------------------------
echo "==> Checking Databricks CLI authentication..."
if ! ME_JSON=$(databricks current-user me "${DBX_FLAGS[@]}" -o json 2>&1); then
  echo "ERROR: Databricks CLI is not authenticated for profile '${PROFILE}'." >&2
  echo "$ME_JSON" >&2
  exit 1
fi

USER_NAME=$(echo "$ME_JSON" | jq -r '.userName // .emails[0].value // "<unknown>"')

# Pull the host the CLI will actually talk to.
AUTH_DESC=$(databricks auth describe "${DBX_FLAGS[@]}" 2>/dev/null || true)
HOST=$(echo "$AUTH_DESC" | awk -F': ' '/host:/ {print $2; exit}' | awk '{print $1}')
HOST="${HOST#https://}"; HOST="${HOST#http://}"; HOST="${HOST%/}"

cat <<EOF

  Profile : ${PROFILE}
  Host    : ${HOST:-<unknown>}
  User    : ${USER_NAME}

EOF

read -r -p "You are currently auth'd into profile '${PROFILE}' - confirm install in this profile [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

# ---------------------------------------------------------------------------
# Step (b): List SQL warehouses and let the user pick one.
# ---------------------------------------------------------------------------
echo
echo "==> Listing SQL warehouses..."
WH_JSON=$(databricks warehouses list "${DBX_FLAGS[@]}" -o json)

WH_COUNT=$(echo "$WH_JSON" | jq 'length')
if [[ "$WH_COUNT" == "0" || -z "$WH_COUNT" ]]; then
  echo "ERROR: No SQL warehouses found in this workspace." >&2
  exit 1
fi

# Render a numbered menu: "  N) <name>  (id=<id>, type=<type>, state=<state>)"
echo "$WH_JSON" | jq -r '
  to_entries[] |
  "  \(.key + 1)) \(.value.name)  (id=\(.value.id), type=\(.value.warehouse_type // "?"), state=\(.value.state // "?"))"
'

echo
read -r -p "Select a warehouse [1-${WH_COUNT}]: " SEL
if ! [[ "$SEL" =~ ^[0-9]+$ ]] || (( SEL < 1 || SEL > WH_COUNT )); then
  echo "ERROR: Invalid selection." >&2
  exit 1
fi

WAREHOUSE_ID=$(echo "$WH_JSON"   | jq -r ".[$((SEL-1))].id")
WAREHOUSE_NAME=$(echo "$WH_JSON" | jq -r ".[$((SEL-1))].name")
echo "Selected: ${WAREHOUSE_NAME} (${WAREHOUSE_ID})"

# Optional parent path. Default to the user's workspace home folder.
if [[ -z "$PARENT_PATH" ]]; then
  DEFAULT_PARENT="/Workspace/Users/${USER_NAME}"
  read -r -p "Parent workspace folder for the Genie space [${DEFAULT_PARENT}]: " PARENT_PATH
  PARENT_PATH="${PARENT_PATH:-$DEFAULT_PARENT}"
fi

# ---------------------------------------------------------------------------
# Step (c): Download the Genie JSON, inject warehouse_id, install via CLI.
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
SRC_JSON="$WORK_DIR/genie_space.json"
BODY_JSON="$WORK_DIR/request_body.json"

echo
echo "==> Downloading Cost Reporting Genie definition (Azure)..."
curl -fsSL "$GENIE_JSON_URL" -o "$SRC_JSON"

echo "==> Building request body..."
jq --arg wid "$WAREHOUSE_ID" --arg pp "$PARENT_PATH" \
  '. + {warehouse_id: $wid, parent_path: $pp}' \
  "$SRC_JSON" > "$BODY_JSON"

echo "==> Creating Genie space (databricks genie create-space)..."
RESP_JSON=$(databricks genie create-space "${DBX_FLAGS[@]}" --json "@${BODY_JSON}" -o json)

echo "$RESP_JSON" | jq .

SPACE_ID=$(echo "$RESP_JSON" | jq -r '.space_id // .id // empty')
echo
echo "Genie space created successfully."
if [[ -n "$SPACE_ID" && -n "$HOST" ]]; then
  echo "Open it: https://${HOST}/genie/rooms/${SPACE_ID}"
fi
