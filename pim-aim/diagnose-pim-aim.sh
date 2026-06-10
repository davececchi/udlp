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
# Requires: az, databricks (>= 0.220), jq
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
# Optional bearer token for Microsoft Graph. `az rest` uses the Azure CLI's
# first-party client token, whose consented delegated scopes do NOT include the
# PIM-for-Groups scopes (PrivilegedAccess.Read.AzureADGroup et al.) — so the PIM
# eligibility/assignment steps [5/9][6/9] WILL fail with PermissionScopeNotGranted
# under `az rest` no matter who is signed in. Supply a token minted WITH those
# scopes (see --help) and every Graph call uses it via curl instead of `az rest`.
GRAPH_TOKEN="${GRAPH_TOKEN:-}"
SCRIPT_VERSION="1.4.0"

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
  --graph-token <jwt>   Bearer token for Microsoft Graph (or set GRAPH_TOKEN). REQUIRED to read
                        PIM-for-Groups data: 'az rest' cannot acquire the PIM scopes, so without
                        this the PIM eligibility/assignment steps fail with PermissionScopeNotGranted.
  --host <url>          Databricks accounts host (default https://accounts.azuredatabricks.net)
  --output <file>       Output JSON path (default pim-aim-diag-<timestamp>.json)
  --help

Preconditions:
  az login
  databricks auth login --host <accounts-host> --account-id <account-id>

Reading PIM-for-Groups data (optional but needed for steps [5/9][6/9]):
  The Azure CLI token used by 'az rest' lacks the PIM-for-Groups Graph scopes, so
  those steps return PermissionScopeNotGranted. To collect them, mint a Graph token
  carrying the scopes and pass it via --graph-token / GRAPH_TOKEN. For example, with
  the Microsoft Graph PowerShell SDK:
    Connect-MgGraph -Scopes PrivilegedAccess.Read.AzureADGroup,\\
      PrivilegedEligibilitySchedule.Read.AzureADGroup,\\
      PrivilegedAssignmentSchedule.Read.AzureADGroup,AuditLog.Read.All
    (Get-MgContext) ; \$tok = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance...
  or any app registration / device-code flow that consents those scopes. The token's
  identity must also hold a role (e.g. Security Reader) to read signInActivity/audit.
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
    --graph-token)       GRAPH_TOKEN="$2"; shift 2 ;;
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

REQUIRED_TOOLS=(az databricks jq)
[[ -n "$GRAPH_TOKEN" ]] && REQUIRED_TOOLS+=(curl)  # token path calls Graph via curl
for tool in "${REQUIRED_TOOLS[@]}"; do
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

# Validate the EXACT path the data calls use, against the --account-id ARG (not
# just the CLI profile). The old preflight ran `databricks account users list`,
# which resolves the account-id from the auth profile and ignores --account-id —
# so a mismatch (arg account-id != authed account, or a workspace-scoped profile)
# passed preflight but then 404'd every dbrest call, silently emptying the whole
# Databricks half. Hitting /accounts/${ACCOUNT_ID}/scim/v2/Users here surfaces
# that immediately.
db_preflight_err="$(mktemp)"
if ! databricks api get "/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/Users?count=1" >/dev/null 2>"$db_preflight_err"; then
  echo "Error: Databricks account SCIM is not reachable for account-id ${ACCOUNT_ID}." >&2
  echo "  Detail: $(tr '\n' ' ' < "$db_preflight_err" | cut -c1-300)" >&2
  echo "  Likely causes:" >&2
  echo "    - --account-id does not match the account the CLI is logged into, OR" >&2
  echo "    - the CLI auth/host is workspace-scoped, not the account console." >&2
  echo "  Fix: databricks auth login --host $DB_HOST --account-id $ACCOUNT_ID" >&2
  echo "       and confirm --account-id matches that login." >&2
  rm -f "$db_preflight_err"
  exit 1
fi
rm -f "$db_preflight_err"

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

# Graph GET. Uses a caller-supplied GRAPH_TOKEN via curl when present (the only
# way to read PIM-for-Groups, since the `az rest` token lacks those scopes),
# otherwise falls back to `az rest`. On failure records the error and returns
# "null", so the run continues AND a later reader can tell a failed/denied call
# apart from a real empty result (which stays a populated object).
graph_call() {
  # Single Graph GET for an absolute URL. Echoes the body; sets rc via return.
  local full="$1" errf="$2"
  if [[ -n "$GRAPH_TOKEN" ]]; then
    local http body
    body=$(curl -sS -w '\n%{http_code}' -H "Authorization: Bearer $GRAPH_TOKEN" \
      -H "Accept: application/json" "$full" 2>"$errf")
    http="${body##*$'\n'}"; body="${body%$'\n'*}"
    if [[ ! "$http" =~ ^2 ]]; then
      # Prefer the response body (Graph's JSON error); fall back to curl's stderr
      # (already in errf) for transport-level failures with no body.
      [[ -n "$body" ]] && printf '%s' "$body" > "$errf"
      [[ ! -s "$errf" ]] && printf 'HTTP %s' "$http" > "$errf"
      return 1
    fi
    printf '%s' "$body"; return 0
  fi
  az rest --method GET --url "$full" 2>"$errf"
}

graph_get() {
  local section="$1" url="$2" version="${3:-v1.0}"
  local out errf rc=0
  errf="$(mktemp)"
  out=$(graph_call "https://graph.microsoft.com/${version}/${url}" "$errf") || rc=$?
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
  local page errf rc guard=0
  # Each page response is appended to a temp file and the pages are merged with
  # `jq -s` at the end. We deliberately do NOT accumulate the merged array in a
  # shell variable passed via `jq --argjson`: for large collections (e.g. a
  # 5k-member group) that argument overflows the OS ARG_MAX and jq aborts with
  # "Argument list too long", silently corrupting the result and the bundle.
  # A single page (~100 rows) is small, so reading nextLink via a pipe is fine.
  local pagesfile; pagesfile="$(mktemp)"
  while [[ -n "$next" && "$next" != "null" ]]; do
    guard=$((guard + 1))
    if [[ "$guard" -gt 100 ]]; then
      record_error "$section" "pagination stopped after 100 pages (possible runaway); with \$top=999 this is ~100k rows — result may be truncated"
      break
    fi
    rc=0; errf="$(mktemp)"
    page=$(graph_call "$next" "$errf") || rc=$?
    if [[ "$rc" -ne 0 ]]; then
      record_error "$section" "$(tr '\n' ' ' < "$errf" | cut -c1-500)"
      rm -f "$errf"; break
    fi
    rm -f "$errf"
    printf '%s\n' "$page" >> "$pagesfile"
    next=$(printf '%s' "$page" | jq -r '."@odata.nextLink" // empty')
  done
  # Slurp every page from the file and concatenate their .value arrays. An empty
  # file (no pages collected) slurps to [] -> {value: []}.
  jq -s '{value: [.[].value[]?]}' "$pagesfile"
  rm -f "$pagesfile"
}

# Databricks account REST via `databricks api get`. This deliberately reuses the
# CLI's own auth resolution (the same path the preflight `account users list`
# check exercises) instead of extracting a bearer token and calling curl
# directly. `databricks auth token` only works with U2M and is keyed by
# host+account-id, so it could disagree with a preflight that passed via a
# profile / env / PAT. `api get` can't drift from the preflight that way.
# On any HTTP/transport error the CLI exits non-zero and writes the detail to
# stderr; we record it and return "null" so the run continues AND a reader can
# tell a failed/denied call apart from a real empty result.
dbrest() {
  local section="$1" path="$2"
  local out errf rc=0
  errf="$(mktemp)"
  out=$(databricks api get "/api/2.0/accounts/${ACCOUNT_ID}/${path}" 2>"$errf") || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    record_error "$section" "$(tr '\n' ' ' < "$errf" | cut -c1-500)"
    rm -f "$errf"; echo "null"; return
  fi
  rm -f "$errf"
  [[ -z "$out" ]] && out="null"
  echo "$out"
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
user_obj=$(graph_get "user" "users/${USER_UPN}?\$select=id,userPrincipalName,displayName,mail,accountEnabled,onPremisesSyncEnabled")
USER_OID=$(echo "$user_obj" | jq -r '.id // empty')
if [[ -z "$USER_OID" ]]; then
  echo "  ERROR: User '$USER_UPN' not found in Entra." >&2
  exit 1
fi
echo "        OID: $USER_OID"

# signInActivity is fetched separately and folded in best-effort. It requires a
# privileged directory role (AuditLog.Read.All / Reports Reader / etc.); if the
# operator lacks it Graph returns 403 for the WHOLE user object. Keeping it out
# of the core select above (which must succeed) means a missing role degrades to
# a recorded error + null signInActivity instead of killing the run at step 1.
user_signin=$(graph_get "user_signInActivity" "users/${USER_OID}?\$select=signInActivity")
user_obj=$(jq -n --argjson u "$user_obj" --argjson s "${user_signin:-null}" \
  '$u + {signInActivity: ($s.signInActivity // null)}')

echo "[2/9] Resolving group in Entra..."
group_obj=$(graph_get "group" "groups/${GROUP_ID}?\$select=id,displayName,description,securityEnabled,mailEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState")
GROUP_NAME=$(echo "$group_obj" | jq -r '.displayName // "unknown"')
echo "        Group: $GROUP_NAME"

echo "[3/9] Direct + transitive group memberships for user..."
user_memberOf=$(graph_get_all "user_memberOf" "users/${USER_OID}/memberOf?\$select=id,displayName&\$top=999")
user_transitiveMemberOf=$(graph_get_all "user_transitiveMemberOf" "users/${USER_OID}/transitiveMemberOf?\$select=id,displayName&\$top=999")

echo "[4/9] Current members of suspect group..."
group_members=$(graph_get_all "group_members" "groups/${GROUP_ID}/members?\$select=id,userPrincipalName,displayName&\$top=999")
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

# The large Graph/SCIM sections are handed to jq via --slurpfile (read from temp
# files), NOT --argjson. A --argjson value for a big collection (e.g. a
# 5k-member group) overflows ARG_MAX and jq aborts with "Argument list too
# long", which used to leave an empty output file. --slurpfile reads the file
# directly; each file holds exactly one JSON doc, so we dereference with [0].
# Small scalars/booleans stay as --arg/--argjson (they never overflow).
BUNDLE_DIR="$(mktemp -d)"
trap 'rm -f "$ERR_FILE"; rm -rf "$BUNDLE_DIR"' EXIT
printf '%s' "${user_obj:-null}"                 > "$BUNDLE_DIR/user"
printf '%s' "${group_obj:-null}"                > "$BUNDLE_DIR/group"
printf '%s' "${user_memberOf:-null}"            > "$BUNDLE_DIR/memberOf"
printf '%s' "${user_transitiveMemberOf:-null}"  > "$BUNDLE_DIR/transitiveMemberOf"
printf '%s' "${group_members:-null}"            > "$BUNDLE_DIR/groupMembers"
printf '%s' "${pim_eligibility:-null}"          > "$BUNDLE_DIR/pimEligibility"
printf '%s' "${pim_assignment_schedules:-null}" > "$BUNDLE_DIR/pimAssignmentSchedules"
printf '%s' "${pim_assignment_instances:-null}" > "$BUNDLE_DIR/pimAssignmentInstances"
printf '%s' "${signins:-null}"                  > "$BUNDLE_DIR/signins"
printf '%s' "${pim_audit_filtered:-null}"       > "$BUNDLE_DIR/pimAudit"
printf '%s' "${db_user_detail:-null}"           > "$BUNDLE_DIR/dbUser"
printf '%s' "${db_group_detail:-null}"          > "$BUNDLE_DIR/dbGroup"
printf '%s' "${db_workspace_assignment:-null}"  > "$BUNDLE_DIR/dbWorkspaceAssignment"

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
  --slurpfile user "$BUNDLE_DIR/user" \
  --slurpfile group "$BUNDLE_DIR/group" \
  --slurpfile memberOf "$BUNDLE_DIR/memberOf" \
  --slurpfile transitiveMemberOf "$BUNDLE_DIR/transitiveMemberOf" \
  --slurpfile groupMembers "$BUNDLE_DIR/groupMembers" \
  --slurpfile pimEligibility "$BUNDLE_DIR/pimEligibility" \
  --slurpfile pimAssignmentSchedules "$BUNDLE_DIR/pimAssignmentSchedules" \
  --slurpfile pimAssignmentInstances "$BUNDLE_DIR/pimAssignmentInstances" \
  --slurpfile signins "$BUNDLE_DIR/signins" \
  --slurpfile pimAudit "$BUNDLE_DIR/pimAudit" \
  --slurpfile dbUser "$BUNDLE_DIR/dbUser" \
  --slurpfile dbGroup "$BUNDLE_DIR/dbGroup" \
  --slurpfile dbWorkspaceAssignment "$BUNDLE_DIR/dbWorkspaceAssignment" \
  --argjson azureUserIsMember "${USER_IS_MEMBER:-false}" \
  --argjson azureUserIsTransitiveMember "${USER_IS_TRANSITIVE_MEMBER:-false}" \
  --argjson activeActivation "${ACTIVE_ACTIVATION:-false}" \
  --argjson dbUserInGroup "${DB_USER_IN_GROUP:-false}" \
  --argjson dbUserListsGroup "${DB_USER_LISTS_GROUP:-false}" \
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
      user: $user[0],
      group: $group[0],
      user_memberOf: $memberOf[0],
      user_transitiveMemberOf: $transitiveMemberOf[0],
      group_current_members: $groupMembers[0],
      pim_eligibility_schedules: $pimEligibility[0],
      pim_active_assignment_schedules: $pimAssignmentSchedules[0],
      pim_active_assignment_instances: $pimAssignmentInstances[0],
      recent_signins: $signins[0],
      pim_audit_events: $pimAudit[0]
    },
    databricks: {
      user: $dbUser[0],
      group: $dbGroup[0],
      workspace_assignment: $dbWorkspaceAssignment[0]
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

# PIM-for-Groups scopes are not obtainable via `az rest`; surface the fix loudly
# so an empty PIM section isn't mistaken for "no eligibility exists".
if echo "$ERRORS" | jq -e 'any(.[]; .error | test("PermissionScopeNotGranted"))' >/dev/null 2>&1; then
  echo ""
  echo "!! PIM eligibility/assignment could NOT be read (PermissionScopeNotGranted)."
  if [[ -z "$GRAPH_TOKEN" ]]; then
    echo "   Cause: 'az rest' uses the Azure CLI token, which lacks PIM-for-Groups"
    echo "          Graph scopes. This is structural, not a per-user permission gap."
    echo "   Fix:   re-run with --graph-token / GRAPH_TOKEN set to a Graph token that"
    echo "          carries PrivilegedAccess.Read.AzureADGroup,"
    echo "          PrivilegedEligibilitySchedule.Read.AzureADGroup,"
    echo "          PrivilegedAssignmentSchedule.Read.AzureADGroup. See --help."
  else
    echo "   A --graph-token was supplied but still lacks the PIM-for-Groups scopes;"
    echo "   re-mint it with the scopes listed in --help (and admin consent if needed)."
  fi
  echo "   The PIM 'eligible-but-not-active' state is exactly what explains a"
  echo "   PIM<->AIM disagreement, so this section is required for a conclusive result."
fi

echo ""
echo "Full JSON saved to: $OUTPUT_FILE"
echo "Attach this file when escalating to Databricks support."
