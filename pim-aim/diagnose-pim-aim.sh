#!/usr/bin/env bash
set -uo pipefail

# Diagnose a single user/group when Azure PIM + Databricks AIM appear to disagree
# on group membership (e.g. user has elevated access in Databricks while their
# PIM assignment is "eligible" but not "active").
#
# Collects from both sides into one JSON file and prints a diff summary:
#   Azure (Entra via Graph):
#     - User profile + recent sign-in activity
#     - Current direct + transitive group memberships
#     - Suspect group's current member list
#     - PIM eligibility schedules (user x group)
#     - PIM active assignment schedules + instances (user x group)
#     - Recent sign-ins (last N days; AAD P1+ required)
#   Databricks (account-level SCIM via AIM):
#     - Account user record (incl. groups)
#     - Account group record (incl. members)
#     - Optional workspace permission assignments
#
# Requires: az, databricks (>= 0.220), jq, curl
#
# Auth prerequisites (run BEFORE this script):
#   az login --tenant <tenant-id>
#   databricks auth login --host https://accounts.azuredatabricks.net --account-id <account-id>

USER_UPN=""
GROUP_ID=""
ACCOUNT_ID="${DATABRICKS_ACCOUNT_ID:-}"
DB_HOST="${DATABRICKS_HOST:-https://accounts.azuredatabricks.net}"
WORKSPACE_ID=""
DAYS=14
DATABRICKS_APP_ID=""
OUTPUT_FILE=""
SCRIPT_VERSION="1.1.0"

usage() {
  cat <<EOF
Diagnose Azure PIM + Databricks AIM elevated-access issue for a specific user/group.

Usage:
  $0 --user <upn> --group <object-id> --account-id <id> [options]

Required:
  --user <upn>          User principal name / email (e.g. alice@contoso.com)
  --group <id>          Entra group object ID (the suspect group)
  --account-id <id>     Databricks account ID (or set DATABRICKS_ACCOUNT_ID)

Optional:
  --workspace-id <id>   Databricks workspace ID to include workspace assignments
  --days <n>            Lookback window for sign-in logs (default 14)
  --databricks-app-id <id>
                        Entra Enterprise App object ID for Databricks (narrows sign-in filter)
  --host <url>          Databricks accounts host (default https://accounts.azuredatabricks.net)
  --output <file>       Output JSON path (default pim-aim-diag-<timestamp>.json)
  --help

Preconditions:
  az login
  databricks auth login --host <accounts-host> --account-id <account-id>
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --user)              USER_UPN="$2"; shift 2 ;;
    --group)             GROUP_ID="$2"; shift 2 ;;
    --account-id)        ACCOUNT_ID="$2"; shift 2 ;;
    --workspace-id)      WORKSPACE_ID="$2"; shift 2 ;;
    --days)              DAYS="$2"; shift 2 ;;
    --databricks-app-id) DATABRICKS_APP_ID="$2"; shift 2 ;;
    --host)              DB_HOST="$2"; shift 2 ;;
    --output)            OUTPUT_FILE="$2"; shift 2 ;;
    --help|-h)           usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[[ -z "$USER_UPN"   ]] && { echo "Error: --user is required" >&2; usage; }
[[ -z "$GROUP_ID"   ]] && { echo "Error: --group is required" >&2; usage; }
[[ -z "$ACCOUNT_ID" ]] && { echo "Error: --account-id is required (or set DATABRICKS_ACCOUNT_ID)" >&2; usage; }

if [[ -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="pim-aim-diag-$(date +%Y%m%d-%H%M%S).json"
fi

# --- Preflight ---

for tool in az databricks jq curl; do
  if ! command -v "$tool" &>/dev/null; then
    echo "Error: required tool '$tool' not found in PATH." >&2
    exit 1
  fi
done

if ! az account show &>/dev/null; then
  echo "Error: 'az' is not signed in. Run 'az login' first." >&2
  exit 1
fi
TENANT_ID=$(az account show --query tenantId -o tsv)

if ! databricks account users list --output json >/dev/null 2>&1; then
  echo "Error: Databricks CLI is not authenticated for account-level access." >&2
  echo "  Run: databricks auth login --host $DB_HOST --account-id $ACCOUNT_ID" >&2
  exit 1
fi

DB_TOKEN=$(databricks auth token --host "$DB_HOST" 2>/dev/null | jq -r '.access_token // empty')
if [[ -z "$DB_TOKEN" ]]; then
  echo "Error: could not extract account-level bearer token from databricks CLI." >&2
  exit 1
fi

# --- Helpers ---

# Errors are appended (one JSON object per line) to a temp file rather than a
# shell variable, because each call below runs in a $(...) subshell — a global
# var mutated inside a subshell would not survive. The file does.
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

record_error() {
  local section="$1" detail="$2"
  jq -cn --arg s "$section" --arg d "$detail" '{section: $s, error: $d}' >> "$ERR_FILE"
}

# az rest -> Graph. On failure records the error and returns "null", so the run
# continues AND a later reader can tell a failed/denied call apart from a real
# empty result (which stays a populated object).
graph_get() {
  local section="$1" url="$2" version="${3:-v1.0}"
  local out errf rc=0
  errf="$(mktemp)"
  out=$(az rest --method GET --url "https://graph.microsoft.com/${version}/${url}" 2>"$errf") || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    record_error "$section" "$(tr '\n' ' ' < "$errf" | cut -c1-500)"
    rm -f "$errf"; echo "null"; return
  fi
  rm -f "$errf"
  [[ -z "$out" ]] && out="null"
  echo "$out"
}

# az rest -> Graph collection, following @odata.nextLink to merge every page.
# Returns {value: [...all pages...]}. Use for any list that can exceed 100 rows
# (group members, memberOf, transitiveMemberOf) so the saved bundle isn't
# silently truncated.
graph_get_all() {
  local section="$1" url="$2" version="${3:-v1.0}"
  local next="https://graph.microsoft.com/${version}/${url}"
  local merged='[]' page errf rc guard=0
  while [[ -n "$next" && "$next" != "null" ]]; do
    guard=$((guard + 1))
    if [[ "$guard" -gt 50 ]]; then
      record_error "$section" "pagination stopped after 50 pages (possible runaway)"
      break
    fi
    rc=0; errf="$(mktemp)"
    page=$(az rest --method GET --url "$next" 2>"$errf") || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      record_error "$section" "$(tr '\n' ' ' < "$errf" | cut -c1-500)"
      rm -f "$errf"; break
    fi
    rm -f "$errf"
    merged=$(jq -n --argjson acc "$merged" --argjson pg "${page:-null}" '$acc + (($pg.value) // [])')
    next=$(echo "$page" | jq -r '."@odata.nextLink" // empty')
  done
  jq -n --argjson v "$merged" '{value: $v}'
}

# Databricks account REST. curl -sS does not fail on HTTP 4xx/5xx, so we capture
# the status code via -w and record any >=400 as an error while still returning
# "null" for the data (keeps "null = no usable data, see .errors" consistent).
dbrest() {
  local section="$1" path="$2"
  local raw rc=0 code body
  raw=$(curl -sS -w $'\n%{http_code}' -H "Authorization: Bearer $DB_TOKEN" \
    "${DB_HOST}/api/2.0/accounts/${ACCOUNT_ID}/${path}" 2>/dev/null) || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    record_error "$section" "curl transport error (rc=$rc)"
    echo "null"; return
  fi
  code="${raw##*$'\n'}"
  body="${raw%$'\n'*}"
  [[ -z "$body" ]] && body="null"
  if [[ "$code" =~ ^[0-9]+$ ]] && [[ "$code" -ge 400 ]]; then
    record_error "$section" "HTTP $code: $(echo "$body" | tr '\n' ' ' | cut -c1-300)"
    echo "null"; return
  fi
  echo "$body"
}

# Lookback window for sign-in logs
if date -v-1d +%s &>/dev/null; then
  SINCE=$(date -u -v-"${DAYS}"d +"%Y-%m-%dT00:00:00Z")
else
  SINCE=$(date -u -d "-${DAYS} days" +"%Y-%m-%dT00:00:00Z")
fi
NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --- Banner ---

echo "Tenant:           $TENANT_ID"
echo "User UPN:         $USER_UPN"
echo "Group ID:         $GROUP_ID"
echo "Databricks acct:  $ACCOUNT_ID"
echo "Output file:      $OUTPUT_FILE"
echo ""

# --- Azure side ---

echo "[1/9] Resolving user in Entra..."
user_obj=$(graph_get "user" "users/${USER_UPN}?\$select=id,userPrincipalName,displayName,mail,accountEnabled,signInActivity,onPremisesSyncEnabled")
USER_OID=$(echo "$user_obj" | jq -r '.id // empty')
if [[ -z "$USER_OID" ]]; then
  echo "  ERROR: User '$USER_UPN' not found in Entra." >&2
  exit 1
fi
echo "        OID: $USER_OID"

echo "[2/9] Resolving group in Entra..."
group_obj=$(graph_get "group" "groups/${GROUP_ID}?\$select=id,displayName,description,securityEnabled,mailEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState")
GROUP_NAME=$(echo "$group_obj" | jq -r '.displayName // "unknown"')
echo "        Group: $GROUP_NAME"

echo "[3/9] Direct + transitive group memberships for user..."
user_memberOf=$(graph_get_all "user_memberOf" "users/${USER_OID}/memberOf?\$select=id,displayName")
user_transitiveMemberOf=$(graph_get_all "user_transitiveMemberOf" "users/${USER_OID}/transitiveMemberOf?\$select=id,displayName")

echo "[4/9] Current members of suspect group..."
group_members=$(graph_get_all "group_members" "groups/${GROUP_ID}/members?\$select=id,userPrincipalName,displayName")
USER_IS_MEMBER=$(echo "$group_members" | jq --arg uid "$USER_OID" '[.value[]? | select(.id == $uid)] | length > 0')

# Also check transitively (group could be reached via nested membership)
USER_IS_TRANSITIVE_MEMBER=$(echo "$user_transitiveMemberOf" | jq --arg gid "$GROUP_ID" '[.value[]? | select(.id == $gid)] | length > 0')

echo "[5/9] PIM eligibility schedules (user x group)..."
pim_eligibility=$(graph_get "pim_eligibility" "identityGovernance/privilegedAccess/group/eligibilitySchedules?\$filter=principalId%20eq%20'${USER_OID}'%20and%20groupId%20eq%20'${GROUP_ID}'")

echo "[6/9] PIM active assignment schedules + currently-active instances..."
pim_assignment_schedules=$(graph_get "pim_assignment_schedules" "identityGovernance/privilegedAccess/group/assignmentSchedules?\$filter=principalId%20eq%20'${USER_OID}'%20and%20groupId%20eq%20'${GROUP_ID}'")
pim_assignment_instances=$(graph_get "pim_assignment_instances" "identityGovernance/privilegedAccess/group/assignmentScheduleInstances?\$filter=principalId%20eq%20'${USER_OID}'%20and%20groupId%20eq%20'${GROUP_ID}'")

ACTIVE_ACTIVATION=$(echo "$pim_assignment_instances" | jq --arg now "$NOW_ISO" \
  '[.value[]? | select((.startDateTime // "0000") <= $now) | select((.endDateTime // "9999") > $now)] | length > 0')

echo "[7/9] Recent sign-ins for user (last ${DAYS}d; AAD P1+ required)..."
signin_filter="userId%20eq%20'${USER_OID}'%20and%20createdDateTime%20ge%20${SINCE}"
if [[ -n "$DATABRICKS_APP_ID" ]]; then
  signin_filter="${signin_filter}%20and%20appId%20eq%20'${DATABRICKS_APP_ID}'"
fi
signins=$(graph_get "signins" "auditLogs/signIns?\$filter=${signin_filter}&\$top=50&\$select=createdDateTime,appDisplayName,appId,clientAppUsed,status,ipAddress")

echo "[8/9] PIM activation audit events for this user x group (last ${DAYS}d)..."
audit_filter="category%20eq%20'RoleManagement'%20and%20activityDateTime%20ge%20${SINCE}"
pim_audit=$(graph_get "pim_audit" "auditLogs/directoryAudits?\$filter=${audit_filter}&\$top=100" "v1.0")
pim_audit_filtered=$(echo "$pim_audit" | jq --arg uid "$USER_OID" --arg gid "$GROUP_ID" '
  {value: [(.value // [])[] | select(
    (.targetResources // [])[]? |
      (.id == $uid) or (.id == $gid)
  )]}
')

# --- Databricks side ---

echo "[9/9] Querying Databricks account (SCIM v2)..."

db_user=$(dbrest "databricks_user_lookup" "scim/v2/Users?filter=userName%20eq%20%22${USER_UPN}%22")
DB_USER_ID=$(echo "$db_user" | jq -r '.Resources[0].id // empty')
if [[ -z "$DB_USER_ID" ]]; then
  # fallback: filter by externalId == Entra OID
  db_user=$(dbrest "databricks_user_lookup_by_externalid" "scim/v2/Users?filter=externalId%20eq%20%22${USER_OID}%22")
  DB_USER_ID=$(echo "$db_user" | jq -r '.Resources[0].id // empty')
fi

if [[ -n "$DB_USER_ID" ]]; then
  db_user_detail=$(dbrest "databricks_user_detail" "scim/v2/Users/${DB_USER_ID}")
else
  db_user_detail="null"
fi

db_group=$(dbrest "databricks_group_lookup" "scim/v2/Groups?filter=externalId%20eq%20%22${GROUP_ID}%22")
DB_GROUP_ID=$(echo "$db_group" | jq -r '.Resources[0].id // empty')
if [[ -n "$DB_GROUP_ID" ]]; then
  db_group_detail=$(dbrest "databricks_group_detail" "scim/v2/Groups/${DB_GROUP_ID}")
else
  db_group_detail="null"
fi

if [[ -n "$DB_GROUP_ID" && -n "$DB_USER_ID" ]]; then
  DB_USER_IN_GROUP=$(echo "$db_group_detail" | jq --arg uid "$DB_USER_ID" \
    '[.members[]? | select(.value == $uid)] | length > 0')
  # Also check user-side: does the user record reference the group?
  DB_USER_LISTS_GROUP=$(echo "$db_user_detail" | jq --arg gid "$DB_GROUP_ID" \
    '[.groups[]? | select(.value == $gid)] | length > 0')
else
  DB_USER_IN_GROUP=false
  DB_USER_LISTS_GROUP=false
fi

db_workspace_assignment="null"
if [[ -n "$WORKSPACE_ID" ]]; then
  db_workspace_assignment=$(dbrest "databricks_workspace_assignment" "workspaces/${WORKSPACE_ID}/permissionassignments")
fi

# --- Build output ---

ERRORS=$(jq -cs '.' "$ERR_FILE" 2>/dev/null); [[ -z "$ERRORS" ]] && ERRORS='[]'

out=$(jq -n \
  --arg ts "$NOW_ISO" \
  --arg script_version "$SCRIPT_VERSION" \
  --argjson errors "$ERRORS" \
  --arg tenant "$TENANT_ID" \
  --arg user_upn "$USER_UPN" \
  --arg user_oid "$USER_OID" \
  --arg group_id "$GROUP_ID" \
  --arg group_name "$GROUP_NAME" \
  --arg account_id "$ACCOUNT_ID" \
  --arg db_user_id "$DB_USER_ID" \
  --arg db_group_id "$DB_GROUP_ID" \
  --argjson user "$user_obj" \
  --argjson group "$group_obj" \
  --argjson memberOf "$user_memberOf" \
  --argjson transitiveMemberOf "$user_transitiveMemberOf" \
  --argjson groupMembers "$group_members" \
  --argjson pimEligibility "$pim_eligibility" \
  --argjson pimAssignmentSchedules "$pim_assignment_schedules" \
  --argjson pimAssignmentInstances "$pim_assignment_instances" \
  --argjson signins "$signins" \
  --argjson pimAudit "$pim_audit_filtered" \
  --argjson dbUser "$db_user_detail" \
  --argjson dbGroup "$db_group_detail" \
  --argjson dbWorkspaceAssignment "$db_workspace_assignment" \
  --argjson azureUserIsMember "$USER_IS_MEMBER" \
  --argjson azureUserIsTransitiveMember "$USER_IS_TRANSITIVE_MEMBER" \
  --argjson activeActivation "$ACTIVE_ACTIVATION" \
  --argjson dbUserInGroup "$DB_USER_IN_GROUP" \
  --argjson dbUserListsGroup "$DB_USER_LISTS_GROUP" \
  '{
    collected_at: $ts,
    script_version: $script_version,
    errors: $errors,
    inputs: {
      tenant_id: $tenant,
      user_upn: $user_upn,
      user_object_id: $user_oid,
      group_id: $group_id,
      group_name: $group_name,
      databricks_account_id: $account_id,
      databricks_user_id: $db_user_id,
      databricks_group_id: $db_group_id
    },
    azure: {
      user: $user,
      group: $group,
      user_memberOf: $memberOf,
      user_transitiveMemberOf: $transitiveMemberOf,
      group_current_members: $groupMembers,
      pim_eligibility_schedules: $pimEligibility,
      pim_active_assignment_schedules: $pimAssignmentSchedules,
      pim_active_assignment_instances: $pimAssignmentInstances,
      recent_signins: $signins,
      pim_audit_events: $pimAudit
    },
    databricks: {
      user: $dbUser,
      group: $dbGroup,
      workspace_assignment: $dbWorkspaceAssignment
    },
    verdicts: {
      azure_user_is_direct_member: $azureUserIsMember,
      azure_user_is_transitive_member: $azureUserIsTransitiveMember,
      azure_pim_activation_currently_active: $activeActivation,
      databricks_group_lists_user_as_member: $dbUserInGroup,
      databricks_user_lists_group: $dbUserListsGroup
    }
  }')

echo "$out" > "$OUTPUT_FILE"

# --- Summary ---

echo ""
echo "=================================================="
echo "DIAGNOSTIC SUMMARY"
echo "=================================================="
echo "User:    $USER_UPN  ($USER_OID)"
echo "Group:   $GROUP_NAME  ($GROUP_ID)"
echo ""
echo "Azure (Entra) ground truth right now:"
echo "  Direct member of group:                $USER_IS_MEMBER"
echo "  Transitive member (via nesting):       $USER_IS_TRANSITIVE_MEMBER"
echo "  Has PIM eligibility for this group:    $(echo "$pim_eligibility" | jq '[.value[]?] | length')"
echo "  PIM activation currently ACTIVE:       $ACTIVE_ACTIVATION"
echo ""
echo "Databricks (account-level via AIM):"
echo "  User exists in account:                $([[ -n "$DB_USER_ID" ]] && echo "yes ($DB_USER_ID)" || echo "no")"
echo "  Group exists in account:               $([[ -n "$DB_GROUP_ID" ]] && echo "yes ($DB_GROUP_ID)" || echo "no")"
echo "  Group's members list contains user:    $DB_USER_IN_GROUP"
echo "  User's groups list contains group:     $DB_USER_LISTS_GROUP"
echo ""
echo "Interpretation:"
if [[ "$USER_IS_MEMBER" == "true" || "$USER_IS_TRANSITIVE_MEMBER" == "true" ]]; then
  if [[ "$ACTIVE_ACTIVATION" == "true" ]]; then
    echo "  Azure shows user as a current member AND PIM activation is live."
    echo "  Expected behavior - access during the activation window."
  else
    echo "  !! Azure shows user as a current member but PIM is NOT active."
    echo "     Investigate for an unintended PERMANENT assignment alongside the"
    echo "     PIM eligibility, or a nested group that grants membership"
    echo "     outside of PIM. See azure.user_memberOf and pim_eligibility_schedules."
  fi
elif [[ "$DB_USER_IN_GROUP" == "true" || "$DB_USER_LISTS_GROUP" == "true" ]]; then
  echo "  !! MISMATCH: Azure says user is NOT in the group, Databricks says YES."
  echo "     Likely causes (in order of likelihood):"
  echo "       1. Stale SCIM-pushed state from before AIM took over (run cleanup)."
  echo "       2. AIM resolution lag - re-check in a few minutes."
  echo "       3. AIM bug. File a Databricks support case with this JSON attached."
else
  echo "  Azure and Databricks agree: user is NOT a member."
  echo "  If the user STILL sees elevated access in the Databricks UI:"
  echo "    - Their browser session is stale; have them fully sign out and sign in."
  echo "    - Check the recent_signins block for prior activations during this session."
fi
ERR_COUNT=$(echo "$ERRORS" | jq 'length')
if [[ "$ERR_COUNT" -gt 0 ]]; then
  echo ""
  echo "NOTE: $ERR_COUNT data-collection error(s) recorded in the bundle (see .errors)."
  echo "      A 'null' section may mean a failed/denied call, not a real absence."
fi

echo ""
echo "Full JSON saved to: $OUTPUT_FILE"
echo "Attach this file when escalating to Databricks support."
