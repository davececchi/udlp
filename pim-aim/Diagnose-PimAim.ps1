#Requires -Version 7.0
<#
.SYNOPSIS
    Diagnose a single user/group when Azure PIM + Databricks AIM appear to disagree
    on group membership.

.DESCRIPTION
    Use case: a user holds elevated Databricks access tied to a group, but that
    group is currently PIM-eligible (not active) for them. This script gathers
    ground truth from both sides and prints a diff summary.

    Collects from:
      Azure (Entra via Graph):
        - User profile + recent sign-in activity
        - Current direct + transitive group memberships
        - Suspect group's current member list
        - PIM eligibility schedules (user x group)
        - PIM active assignment schedules + instances (user x group)
        - Recent sign-ins (last N days; AAD P1+ required)
        - PIM directory audit events
      Databricks (account-level SCIM via AIM):
        - Account user record (incl. groups)
        - Account group record (incl. members)
        - Optional workspace permission assignments

    Requires: az CLI, databricks CLI (>= 0.220), PowerShell 7+

    Auth prerequisites (run BEFORE this script):
      az login --tenant <tenant-id>
      databricks auth login --host https://accounts.azuredatabricks.net --account-id <account-id>

.PARAMETER User
    User principal name / email (e.g. alice@contoso.com).

.PARAMETER GroupId
    Entra group object ID (the suspect group).

.PARAMETER AccountId
    Databricks account ID. Falls back to $env:DATABRICKS_ACCOUNT_ID.

.PARAMETER WorkspaceId
    Optional Databricks workspace ID to include workspace permission assignments.

.PARAMETER Days
    Lookback window for sign-in / audit logs (default 14).

.PARAMETER DatabricksAppId
    Optional Entra Enterprise App object ID for Databricks (narrows sign-in filter).

.PARAMETER DbHost
    Databricks accounts host (default https://accounts.azuredatabricks.net).

.PARAMETER GraphToken
    Bearer token for Microsoft Graph (falls back to $env:GRAPH_TOKEN). REQUIRED to
    read PIM-for-Groups data: 'az rest' uses the Azure CLI's first-party token, whose
    consented scopes do NOT include the PIM-for-Groups scopes
    (PrivilegedAccess.Read.AzureADGroup et al.), so the PIM eligibility/assignment
    steps fail with PermissionScopeNotGranted no matter who is signed in. Mint a token
    carrying those scopes (e.g. Connect-MgGraph -Scopes PrivilegedAccess.Read.AzureADGroup,
    PrivilegedEligibilitySchedule.Read.AzureADGroup,
    PrivilegedAssignmentSchedule.Read.AzureADGroup,AuditLog.Read.All) and pass it here;
    every Graph call then uses it via Invoke-RestMethod instead of 'az rest'.

.PARAMETER Output
    Output JSON path (default pim-aim-diag-<timestamp>.json).

.EXAMPLE
    .\Diagnose-PimAim.ps1 -User alice@contoso.com -GroupId 1111-... -AccountId 2222-...

.EXAMPLE
    .\Diagnose-PimAim.ps1 -User alice@contoso.com -GroupId 1111-... -AccountId 2222-... `
        -WorkspaceId 1234567890 -Days 30 -Output .\alice-diag.json
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Interactive diagnostic tool; console output is intentional.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$User,
    [Parameter(Mandatory=$true)][string]$GroupId,
    [string]$AccountId = $env:DATABRICKS_ACCOUNT_ID,
    [string]$WorkspaceId,
    [int]$Days = 14,
    [string]$DatabricksAppId,
    [string]$DbHost = "https://accounts.azuredatabricks.net",
    [string]$GraphToken = $env:GRAPH_TOKEN,
    [string]$Output
)

$ErrorActionPreference = "Stop"
$ScriptVersion = "1.4.0"

if (-not $AccountId) {
    Write-Error "-AccountId is required (or set DATABRICKS_ACCOUNT_ID)."
}

if (-not $Output) {
    $Output = "pim-aim-diag-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

# --- Preflight ---

foreach ($tool in @("az", "databricks")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "'$tool' not found in PATH."
    }
}

$null = az account show 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "'az' is not signed in. Run 'az login' first."
}
$TenantId = (az account show --query tenantId -o tsv).Trim()

# Validate the EXACT path the data calls use, against the -AccountId ARG (not just
# the CLI profile). `databricks account users list` resolves the account-id from
# the auth profile and ignores -AccountId, so a mismatch (arg != authed account, or
# a workspace-scoped profile) passed preflight but then 404'd every data call,
# silently emptying the whole Databricks half. Hitting /accounts/$AccountId/... here
# surfaces that immediately.
$dbErrFile = New-TemporaryFile
$null = databricks api get "/api/2.0/accounts/$AccountId/scim/v2/Users?count=1" 2>$dbErrFile.FullName
if ($LASTEXITCODE -ne 0) {
    $detail = (((Get-Content $dbErrFile.FullName -Raw) -replace '\s+', ' ').Trim())
    if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) }
    Remove-Item $dbErrFile -Force
    Write-Error @"
Databricks account SCIM is not reachable for account-id $AccountId.
  Detail: $detail
  Likely causes:
    - -AccountId does not match the account the CLI is logged into, OR
    - the CLI auth/host is workspace-scoped, not the account console.
  Fix: databricks auth login --host $DbHost --account-id $AccountId
       and confirm -AccountId matches that login.
"@
}
Remove-Item $dbErrFile -Force

# --- Helpers ---

# Records data-collection failures so a later reader can tell a failed/denied
# call apart from a genuine empty result (which stays a populated object).
$CollectionErrors = [System.Collections.Generic.List[object]]::new()

function Add-CollectionError {
    param([string]$Section, [string]$Detail)
    $msg = (($Detail | Out-String) -replace '\s+', ' ').Trim()
    if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
    $CollectionErrors.Add([ordered]@{ section = $Section; error = $msg }) | Out-Null
}

# Single Graph GET for an absolute URL. Uses $GraphToken via Invoke-RestMethod
# when present (the only way to read PIM-for-Groups, since the `az rest` token
# lacks those scopes), otherwise falls back to `az rest`. Returns the parsed
# object, or throws with the error detail so callers can record it.
function Invoke-GraphCall {
    param([string]$Full)
    if ($GraphToken) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Full `
                -Headers @{ Authorization = "Bearer $GraphToken"; Accept = "application/json" }
        } catch {
            $detail = $_.ErrorDetails.Message
            if (-not $detail) { $detail = $_.Exception.Message }
            throw $detail
        }
    }
    $errFile = New-TemporaryFile
    $raw = az rest --method GET --url $Full 2>$errFile.FullName
    $rc = $LASTEXITCODE
    $err = Get-Content $errFile.FullName -Raw
    Remove-Item $errFile -Force
    if ($rc -ne 0) { throw $err }
    if (-not $raw) { return $null }
    return $raw | ConvertFrom-Json -Depth 20
}

function Invoke-Graph {
    param(
        [string]$Section,
        [string]$Url,
        [string]$Version = "v1.0"
    )
    $full = "https://graph.microsoft.com/$Version/$Url"
    try {
        return Invoke-GraphCall $full
    } catch {
        Add-CollectionError $Section ($_.Exception.Message)
        return $null
    }
}

# Graph collection that follows @odata.nextLink to merge every page. Returns an
# object with a .value array of all rows, so the saved bundle isn't silently
# truncated at 100 for large groups / heavily-grouped users.
function Invoke-GraphAll {
    param(
        [string]$Section,
        [string]$Url,
        [string]$Version = "v1.0"
    )
    $next = "https://graph.microsoft.com/$Version/$Url"
    $items = [System.Collections.Generic.List[object]]::new()
    $guard = 0
    while ($next) {
        $guard++
        if ($guard -gt 100) {
            Add-CollectionError $Section "pagination stopped after 100 pages (possible runaway); with `$top=999 this is ~100k rows - result may be truncated"
            break
        }
        $page = $null
        try { $page = Invoke-GraphCall $next } catch {
            Add-CollectionError $Section ($_.Exception.Message)
            break
        }
        if ($page.value) { foreach ($v in $page.value) { $items.Add($v) } }
        $next = $page.'@odata.nextLink'
    }
    return [pscustomobject]@{ value = $items.ToArray() }
}

# Databricks account REST via `databricks api get`. Reuses the CLI's own auth
# resolution (the same /accounts/$AccountId/... path the preflight now exercises)
# rather than extracting a bearer token: `databricks auth token` only works with
# U2M and is keyed by host+account-id, so it could disagree with a preflight
# that passed via a profile / env / PAT. `api get` can't drift that way. On any
# HTTP/transport error the CLI exits non-zero and writes detail to stderr; we
# record it and return $null, keeping the bundle's "null = no usable data, see
# .errors" contract consistent.
function Invoke-DbRest {
    param([string]$Section, [string]$Path)
    $errFile = New-TemporaryFile
    $raw = databricks api get "/api/2.0/accounts/$AccountId/$Path" 2>$errFile.FullName
    if ($LASTEXITCODE -ne 0) {
        Add-CollectionError $Section (Get-Content $errFile.FullName -Raw)
        Remove-Item $errFile -Force
        return $null
    }
    Remove-Item $errFile -Force
    if (-not $raw) { return $null }
    try { return $raw | ConvertFrom-Json -Depth 20 } catch {
        Add-CollectionError $Section "JSON parse failure"
        return $null
    }
}

$nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$sinceIso = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString("yyyy-MM-ddT00:00:00Z")

# --- Banner ---

Write-Host "Tenant:           $TenantId"
Write-Host "User UPN:         $User"
Write-Host "Group ID:         $GroupId"
Write-Host "Databricks acct:  $AccountId"
Write-Host "Output file:      $Output"
Write-Host ""

# --- Azure side ---

Write-Host "[1/9] Resolving user in Entra..."
$userObj = Invoke-Graph "user" "users/$User`?`$select=id,userPrincipalName,displayName,mail,accountEnabled,onPremisesSyncEnabled"
$UserOid = $userObj.id
if (-not $UserOid) {
    Write-Error "User '$User' not found in Entra."
}
Write-Host "        OID: $UserOid"

# signInActivity needs a privileged directory role (AuditLog.Read.All / Reports
# Reader / etc.). If the operator lacks it, Graph returns 403 for the WHOLE user
# object. Fetch it separately and fold it in best-effort so a missing role
# degrades to a recorded error + null signInActivity instead of killing step 1.
$userSignin = Invoke-Graph "user_signInActivity" "users/$UserOid`?`$select=signInActivity"
$userObj | Add-Member -NotePropertyName signInActivity -NotePropertyValue ($userSignin.signInActivity) -Force

Write-Host "[2/9] Resolving group in Entra..."
$groupObj = Invoke-Graph "group" "groups/$GroupId`?`$select=id,displayName,description,securityEnabled,mailEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState"
$GroupName = if ($groupObj.displayName) { $groupObj.displayName } else { "unknown" }
Write-Host "        Group: $GroupName"

Write-Host "[3/9] Direct + transitive group memberships for user..."
$userMemberOf = Invoke-GraphAll "user_memberOf" "users/$UserOid/memberOf`?`$select=id,displayName&`$top=999"
$userTransitiveMemberOf = Invoke-GraphAll "user_transitiveMemberOf" "users/$UserOid/transitiveMemberOf`?`$select=id,displayName&`$top=999"

Write-Host "[4/9] Current members of suspect group..."
$groupMembers = Invoke-GraphAll "group_members" "groups/$GroupId/members`?`$select=id,userPrincipalName,displayName&`$top=999"
$UserIsMember = [bool](($groupMembers.value | Where-Object { $_.id -eq $UserOid }).Count)
$UserIsTransitiveMember = [bool](($userTransitiveMemberOf.value | Where-Object { $_.id -eq $GroupId }).Count)

Write-Host "[5/9] PIM eligibility schedules (user x group)..."
$pimEligibility = Invoke-Graph "pim_eligibility" "identityGovernance/privilegedAccess/group/eligibilitySchedules`?`$filter=principalId%20eq%20'$UserOid'%20and%20groupId%20eq%20'$GroupId'"

Write-Host "[6/9] PIM active assignment schedules + currently-active instances..."
$pimAssignmentSchedules = Invoke-Graph "pim_assignment_schedules" "identityGovernance/privilegedAccess/group/assignmentSchedules`?`$filter=principalId%20eq%20'$UserOid'%20and%20groupId%20eq%20'$GroupId'"
$pimAssignmentInstances = Invoke-Graph "pim_assignment_instances" "identityGovernance/privilegedAccess/group/assignmentScheduleInstances`?`$filter=principalId%20eq%20'$UserOid'%20and%20groupId%20eq%20'$GroupId'"

$ActiveActivation = $false
if ($pimAssignmentInstances.value) {
    $ActiveActivation = [bool]($pimAssignmentInstances.value | Where-Object {
        $start = if ($_.startDateTime) { $_.startDateTime } else { "0000" }
        $end = if ($_.endDateTime) { $_.endDateTime } else { "9999" }
        ($start -le $nowIso) -and ($end -gt $nowIso)
    }).Count
}

Write-Host "[7/9] Recent sign-ins for user (last $Days d; AAD P1+ required)..."
$signinFilter = "userId%20eq%20'$UserOid'%20and%20createdDateTime%20ge%20$sinceIso"
if ($DatabricksAppId) {
    $signinFilter += "%20and%20appId%20eq%20'$DatabricksAppId'"
}
$signins = Invoke-Graph "signins" "auditLogs/signIns`?`$filter=$signinFilter&`$top=50&`$select=createdDateTime,appDisplayName,appId,clientAppUsed,status,ipAddress"

Write-Host "[8/9] PIM activation audit events for this user x group (last $Days d)..."
$auditFilter = "category%20eq%20'RoleManagement'%20and%20activityDateTime%20ge%20$sinceIso"
$pimAudit = Invoke-Graph "pim_audit" "auditLogs/directoryAudits`?`$filter=$auditFilter&`$top=100"
$pimAuditFiltered = @{ value = @() }
if ($pimAudit.value) {
    $pimAuditFiltered.value = @($pimAudit.value | Where-Object {
        $targets = $_.targetResources
        $targets -and ($targets | Where-Object { $_.id -eq $UserOid -or $_.id -eq $GroupId })
    })
}

# --- Databricks side ---

Write-Host "[9/9] Querying Databricks account (SCIM v2)..."

$encodedUpn = [System.Net.WebUtility]::UrlEncode($User)
$dbUser = Invoke-DbRest "databricks_user_lookup" "scim/v2/Users?filter=userName%20eq%20%22$encodedUpn%22"
$DbUserId = $dbUser.Resources[0].id
if (-not $DbUserId) {
    $dbUser = Invoke-DbRest "databricks_user_lookup_by_externalid" "scim/v2/Users?filter=externalId%20eq%20%22$UserOid%22"
    $DbUserId = $dbUser.Resources[0].id
}

$dbUserDetail = if ($DbUserId) { Invoke-DbRest "databricks_user_detail" "scim/v2/Users/$DbUserId" } else { $null }

$dbGroup = Invoke-DbRest "databricks_group_lookup" "scim/v2/Groups?filter=externalId%20eq%20%22$GroupId%22"
$DbGroupId = $dbGroup.Resources[0].id
$dbGroupDetail = if ($DbGroupId) { Invoke-DbRest "databricks_group_detail" "scim/v2/Groups/$DbGroupId" } else { $null }

$DbUserInGroup = $false
$DbUserListsGroup = $false
if ($DbGroupId -and $DbUserId) {
    $DbUserInGroup   = [bool](($dbGroupDetail.members | Where-Object { $_.value -eq $DbUserId }).Count)
    $DbUserListsGroup = [bool](($dbUserDetail.groups  | Where-Object { $_.value -eq $DbGroupId }).Count)
}

$dbWorkspaceAssignment = $null
if ($WorkspaceId) {
    $dbWorkspaceAssignment = Invoke-DbRest "databricks_workspace_assignment" "workspaces/$WorkspaceId/permissionassignments"
}

# --- Build output ---

$out = [ordered]@{
    collected_at = $nowIso
    script_version = $ScriptVersion
    errors = $CollectionErrors.ToArray()
    inputs = [ordered]@{
        tenant_id              = $TenantId
        user_upn               = $User
        user_object_id         = $UserOid
        group_id               = $GroupId
        group_name             = $GroupName
        databricks_account_id  = $AccountId
        databricks_user_id     = $DbUserId
        databricks_group_id    = $DbGroupId
    }
    azure = [ordered]@{
        user                              = $userObj
        group                             = $groupObj
        user_memberOf                     = $userMemberOf
        user_transitiveMemberOf           = $userTransitiveMemberOf
        group_current_members             = $groupMembers
        pim_eligibility_schedules         = $pimEligibility
        pim_active_assignment_schedules   = $pimAssignmentSchedules
        pim_active_assignment_instances   = $pimAssignmentInstances
        recent_signins                    = $signins
        pim_audit_events                  = $pimAuditFiltered
    }
    databricks = [ordered]@{
        user                  = $dbUserDetail
        group                 = $dbGroupDetail
        workspace_assignment  = $dbWorkspaceAssignment
    }
    verdicts = [ordered]@{
        azure_user_is_direct_member            = $UserIsMember
        azure_user_is_transitive_member        = $UserIsTransitiveMember
        azure_pim_activation_currently_active  = $ActiveActivation
        databricks_group_lists_user_as_member  = $DbUserInGroup
        databricks_user_lists_group            = $DbUserListsGroup
    }
}

$out | ConvertTo-Json -Depth 20 | Set-Content -Path $Output -Encoding utf8

# --- Summary ---

$elig = if ($pimEligibility.value) { $pimEligibility.value.Count } else { 0 }

Write-Host ""
Write-Host "=================================================="
Write-Host "DIAGNOSTIC SUMMARY"
Write-Host "=================================================="
Write-Host "User:    $User  ($UserOid)"
Write-Host "Group:   $GroupName  ($GroupId)"
Write-Host ""
Write-Host "Azure (Entra) ground truth right now:"
Write-Host "  Direct member of group:                $UserIsMember"
Write-Host "  Transitive member (via nesting):       $UserIsTransitiveMember"
Write-Host "  Has PIM eligibility for this group:    $elig"
Write-Host "  PIM activation currently ACTIVE:       $ActiveActivation"
Write-Host ""
Write-Host "Databricks (account-level via AIM):"
$userExists  = if ($DbUserId)  { "yes ($DbUserId)" }  else { "no" }
$groupExists = if ($DbGroupId) { "yes ($DbGroupId)" } else { "no" }
Write-Host "  User exists in account:                $userExists"
Write-Host "  Group exists in account:               $groupExists"
Write-Host "  Group's members list contains user:    $DbUserInGroup"
Write-Host "  User's groups list contains group:     $DbUserListsGroup"
Write-Host ""
Write-Host "Interpretation:"
if ($UserIsMember -or $UserIsTransitiveMember) {
    if ($ActiveActivation) {
        Write-Host "  Azure shows user as a current member AND PIM activation is live."
        Write-Host "  Expected behavior - access during the activation window."
    } else {
        Write-Host "  !! Azure shows user as a current member but PIM is NOT active."
        Write-Host "     Investigate for an unintended PERMANENT assignment alongside the"
        Write-Host "     PIM eligibility, or a nested group that grants membership"
        Write-Host "     outside of PIM. See azure.user_memberOf and pim_eligibility_schedules."
    }
} elseif ($DbUserInGroup -or $DbUserListsGroup) {
    Write-Host "  !! MISMATCH: Azure says user is NOT in the group, Databricks says YES."
    Write-Host "     Likely causes (in order of likelihood):"
    Write-Host "       1. Stale SCIM-pushed state from before AIM took over (run cleanup)."
    Write-Host "       2. AIM resolution lag - re-check in a few minutes."
    Write-Host "       3. AIM bug. File a Databricks support case with this JSON attached."
} else {
    Write-Host "  Azure and Databricks agree: user is NOT a member."
    Write-Host "  If the user STILL sees elevated access in the Databricks UI:"
    Write-Host "    - Their browser session is stale; have them fully sign out and sign in."
    Write-Host "    - Check the recent_signins block for prior activations during this session."
}
if ($CollectionErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "NOTE: $($CollectionErrors.Count) data-collection error(s) recorded in the bundle (see .errors)."
    Write-Host "      A 'null' section may mean a failed/denied call, not a real absence."
}

# PIM-for-Groups scopes are not obtainable via `az rest`; surface the fix loudly
# so an empty PIM section isn't mistaken for "no eligibility exists".
if ($CollectionErrors | Where-Object { $_.error -match 'PermissionScopeNotGranted' }) {
    Write-Host ""
    Write-Host "!! PIM eligibility/assignment could NOT be read (PermissionScopeNotGranted)."
    if (-not $GraphToken) {
        Write-Host "   Cause: 'az rest' uses the Azure CLI token, which lacks PIM-for-Groups"
        Write-Host "          Graph scopes. This is structural, not a per-user permission gap."
        Write-Host "   Fix:   re-run with -GraphToken / GRAPH_TOKEN set to a Graph token that"
        Write-Host "          carries PrivilegedAccess.Read.AzureADGroup,"
        Write-Host "          PrivilegedEligibilitySchedule.Read.AzureADGroup,"
        Write-Host "          PrivilegedAssignmentSchedule.Read.AzureADGroup. See Get-Help -Full."
    } else {
        Write-Host "   A -GraphToken was supplied but still lacks the PIM-for-Groups scopes;"
        Write-Host "   re-mint it with those scopes (and admin consent if needed)."
    }
    Write-Host "   The PIM 'eligible-but-not-active' state is exactly what explains a"
    Write-Host "   PIM<->AIM disagreement, so this section is required for a conclusive result."
}

Write-Host ""
Write-Host "Full JSON saved to: $Output"
Write-Host "Attach this file when escalating to Databricks support."
