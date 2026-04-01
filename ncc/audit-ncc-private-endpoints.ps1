#Requires -Version 7.0
<#
.SYNOPSIS
    Audit NCC private endpoint rules to find unused/stale endpoints.

.DESCRIPTION
    Identifies Databricks NCC private endpoint rules that likely have no traffic
    and are candidates for deletion.

    Classification signals:
      1. connection_state: REJECTED/DISCONNECTED/EXPIRED = definitively unused
      2. Azure Monitor: Transactions metric on target storage accounts (-CheckAzure)
      3. Age: PENDING rules older than threshold were never approved

    Requires: databricks CLI (account-level auth)
    Optional: az CLI (for -CheckAzure)

.EXAMPLE
    .\audit-ncc-private-endpoints.ps1
    Interactive NCC selection, default 60-day lookback.

.EXAMPLE
    .\audit-ncc-private-endpoints.ps1 -All -CheckAzure -Days 90
    Audit all NCCs, check Azure Monitor metrics, 90-day lookback.

.EXAMPLE
    .\audit-ncc-private-endpoints.ps1 -NccId "abc-123" -Json
    Audit specific NCC, output as JSON.

.EXAMPLE
    .\audit-ncc-private-endpoints.ps1 -All -Delete
    Audit all NCCs and interactively prompt to delete flagged rules.
#>

[CmdletBinding()]
param(
    [string]$NccId,
    [switch]$All,
    [int]$Days = 60,
    [switch]$CheckAzure,
    [switch]$Json,
    [switch]$Delete
)

$ErrorActionPreference = "Stop"

# --- Preflight ---

function Test-Prerequisites {
    if (-not (Get-Command "databricks" -ErrorAction SilentlyContinue)) {
        Write-Error "databricks CLI not found. Install from https://docs.databricks.com/dev-tools/cli"
    }
    if ($CheckAzure -and -not (Get-Command "az" -ErrorAction SilentlyContinue)) {
        Write-Error "-CheckAzure requires the Azure CLI (az). Install from https://aka.ms/installazurecli"
    }
}

Test-Prerequisites

$CutoffDate = (Get-Date).AddDays(-$Days)
$CutoffMs = [long]([DateTimeOffset]$CutoffDate).ToUnixTimeMilliseconds()

# --- Helpers ---

function Write-Log {
    param([string]$Message)
    if (-not $Json) { Write-Host $Message }
}

function Get-NccList {
    $raw = databricks account network-connectivity list-network-connectivity-configurations --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error @"
Failed to list NCCs. Ensure Databricks CLI has account-level auth configured.
  `$env:DATABRICKS_HOST = "https://accounts.azuredatabricks.net"  (or accounts.cloud.databricks.com)
  `$env:DATABRICKS_ACCOUNT_ID = "<your-account-id>"
"@
    }
    return $raw | ConvertFrom-Json
}

function Select-NccInteractive {
    param([array]$NccList)

    if ($NccList.Count -eq 0) {
        Write-Error "No NCCs found in this account."
    }

    Write-Host ""
    Write-Host "Available NCCs:"
    Write-Host "---"
    for ($i = 0; $i -lt $NccList.Count; $i++) {
        $ncc = $NccList[$i]
        $name = if ($ncc.name) { $ncc.name } else { "unnamed" }
        $region = if ($ncc.region) { $ncc.region } else { "unknown" }
        Write-Host "  [$($i + 1)] $name ($region) - $($ncc.network_connectivity_config_id)"
    }
    Write-Host ""

    $selection = Read-Host "Select an NCC [1-$($NccList.Count)]"
    $idx = [int]$selection - 1
    if ($idx -lt 0 -or $idx -ge $NccList.Count) {
        Write-Error "Invalid selection"
    }

    return $NccList[$idx].network_connectivity_config_id
}

function Format-Timestamp {
    param([long]$EpochMs)
    if ($EpochMs -le 0) { return "N/A" }
    return [DateTimeOffset]::FromUnixTimeMilliseconds($EpochMs).DateTime.ToString("yyyy-MM-dd")
}

function Get-ShortName {
    param([string]$ResourceId)
    if ([string]::IsNullOrEmpty($ResourceId)) { return "N/A" }
    return ($ResourceId -split "/")[-1]
}

# Query Azure Monitor for storage account Transactions over the lookback window.
# Returns a hashtable: @{ Status = "true"|"false"|"skipped"|"unknown"; Transactions = <count> }
function Test-AzureTraffic {
    param([string]$ResourceId)

    if (-not $CheckAzure) {
        return @{ Status = "skipped"; Transactions = $null }
    }

    # Only storage accounts supported
    if ($ResourceId -notmatch "Microsoft\.Storage/storageAccounts") {
        return @{ Status = "unknown"; Transactions = $null }
    }

    $startTime = $CutoffDate.ToUniversalTime().ToString("yyyy-MM-ddT00:00:00Z")
    $endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddT23:59:59Z")

    try {
        $raw = az monitor metrics list `
            --resource $ResourceId `
            --metric "Transactions" `
            --aggregation Total `
            --start-time $startTime `
            --end-time $endTime `
            --interval P1D `
            --output json 2>$null

        if ($LASTEXITCODE -ne 0) {
            return @{ Status = "unknown"; Transactions = $null }
        }

        $metrics = $raw | ConvertFrom-Json
        [long]$total = 0
        foreach ($ts in $metrics.value[0].timeseries) {
            foreach ($dp in $ts.data) {
                if ($dp.total) { $total += [long]$dp.total }
            }
        }

        if ($total -gt 0) {
            return @{ Status = "true"; Transactions = $total }
        }
        else {
            return @{ Status = "false"; Transactions = 0 }
        }
    }
    catch {
        return @{ Status = "unknown"; Transactions = $null }
    }
}

# Format a number with comma separators: 1234567 -> 1,234,567
function Format-Number {
    param([long]$Value)
    return $Value.ToString("N0")
}

# --- Main ---

$nccIds = @()

if ($NccId) {
    $nccIds += $NccId
}
elseif ($All) {
    Write-Log "Fetching all NCCs..."
    $nccList = Get-NccList
    $nccIds = $nccList | ForEach-Object { $_.network_connectivity_config_id }
    Write-Log "Found $($nccIds.Count) NCC(s)"
}
else {
    $nccList = Get-NccList
    $selected = Select-NccInteractive -NccList $nccList
    $nccIds += $selected
}

$allResults = @()
$totalRules = 0
$flaggedRules = 0

foreach ($nccId in $nccIds) {
    Write-Log ""
    Write-Log "Auditing NCC: $nccId"
    Write-Log ("=" * 60)

    try {
        $raw = databricks account network-connectivity list-private-endpoint-rules $nccId --output json 2>&1
        if ($LASTEXITCODE -ne 0) { throw "CLI error: $raw" }
        $rules = $raw | ConvertFrom-Json
    }
    catch {
        Write-Log "  Warning: Failed to list rules for NCC ${nccId}: $_"
        continue
    }

    if (-not $rules -or $rules.Count -eq 0) {
        Write-Log "  No private endpoint rules found."
        continue
    }

    Write-Log "  Found $($rules.Count) rule(s). Analyzing..."
    if ($CheckAzure) { Write-Log "  (Querying Azure Monitor for each storage account - this may take a moment)" }
    Write-Log ""

    foreach ($rule in $rules) {
        $ruleId = $rule.rule_id
        $resourceId = if ($rule.resource_id) { $rule.resource_id } else { "N/A" }
        $groupId = if ($rule.group_id) { $rule.group_id } else { "N/A" }
        $state = if ($rule.connection_state) { $rule.connection_state } else { "UNKNOWN" }
        $creationTime = if ($rule.creation_time) { [long]$rule.creation_time } else { 0 }
        $updatedTime = if ($rule.updated_time) { [long]$rule.updated_time } else { 0 }
        $deactivated = if ($rule.deactivated) { $rule.deactivated } else { $false }

        # --- Classify inline to capture transaction counts ---
        $classification = ""
        $transactions = $null
        $txnsDisplay = ""

        if ($deactivated -eq $true) {
            $classification = "DEACTIVATED"
        }
        elseif ($state -in @("REJECTED", "DISCONNECTED", "EXPIRED")) {
            $classification = "DEAD:$state"
        }
        elseif ($state -eq "PENDING") {
            if ($creationTime -gt 0 -and $creationTime -lt $CutoffMs) {
                $classification = "STALE_PENDING"
            }
            else {
                $classification = "PENDING"
            }
        }
        else {
            # ESTABLISHED - check Azure metrics
            $azResult = Test-AzureTraffic -ResourceId $resourceId
            $transactions = $azResult.Transactions

            switch ($azResult.Status) {
                "false" { $classification = "NO_TRAFFIC" }
                "true"  { $classification = "ACTIVE" }
                default {
                    if ($updatedTime -gt 0 -and $updatedTime -lt $CutoffMs) {
                        $classification = "LIKELY_UNUSED"
                    }
                    else {
                        $classification = "UNKNOWN"
                    }
                }
            }
        }

        # Format transaction count for display
        if ($null -ne $transactions) {
            $txnsDisplay = Format-Number -Value $transactions
        }

        $flagged = $classification -match "^(DEAD:|STALE_PENDING|NO_TRAFFIC|DEACTIVATED|LIKELY_UNUSED)"

        $totalRules++
        if ($flagged) { $flaggedRules++ }

        $createdStr = Format-Timestamp -EpochMs $creationTime
        $updatedStr = Format-Timestamp -EpochMs $updatedTime
        $resourceShort = Get-ShortName -ResourceId $resourceId

        $entry = [PSCustomObject]@{
            ncc_id         = $nccId
            rule_id        = $ruleId
            resource_id    = $resourceId
            resource_short = $resourceShort
            group_id       = $groupId
            state          = $state
            classification = $classification
            flagged        = $flagged
            created        = $createdStr
            updated        = $updatedStr
            transactions   = if ($null -ne $transactions) { $transactions.ToString() } else { "" }
        }
        $allResults += $entry

        if (-not $Json) {
            $icon = if ($flagged) { "!!" } else { "ok" }
            Write-Host ("  [{0}] {1,-25} {2,-8} {3,-16}  Created: {4}  Updated: {5}" -f `
                $icon, $resourceShort, $groupId, $classification, $createdStr, $updatedStr)
            Write-Host "        Rule: $ruleId"
            Write-Host "        Resource: $resourceId"
            if ($txnsDisplay) {
                Write-Host "        Transactions (${Days}d): $txnsDisplay"
            }
            Write-Host ""
        }
    }
}

# --- Summary ---

if ($Json) {
    $classGroups = @{}
    foreach ($r in $allResults) {
        if (-not $classGroups.ContainsKey($r.classification)) {
            $classGroups[$r.classification] = 0
        }
        $classGroups[$r.classification]++
    }

    $output = [PSCustomObject]@{
        summary = [PSCustomObject]@{
            total_rules       = $totalRules
            flagged_rules     = $flaggedRules
            by_classification = $classGroups
        }
        flagged   = @($allResults | Where-Object { $_.flagged })
        all_rules = $allResults
    }
    $output | ConvertTo-Json -Depth 5
    exit 0
}

Write-Host ""
Write-Host ("=" * 60)
Write-Host "AUDIT SUMMARY ($Days-day lookback)"
Write-Host ("=" * 60)
Write-Host "  Total rules scanned:  $totalRules"
Write-Host "  Flagged for review:   $flaggedRules"
Write-Host ""

$classLabels = @{
    "DEAD:REJECTED"     = "Rejected (never approved by resource owner)"
    "DEAD:DISCONNECTED" = "Disconnected"
    "DEAD:EXPIRED"      = "Expired"
    "STALE_PENDING"     = "Pending > $Days days (never approved)"
    "NO_TRAFFIC"        = "Zero transactions on storage account (${Days}d)"
    "LIKELY_UNUSED"     = "Likely unused (no config change in ${Days}d, no Azure data)"
    "DEACTIVATED"       = "Already deactivated (pending deletion)"
}

foreach ($class in $classLabels.Keys) {
    $count = @($allResults | Where-Object { $_.classification -eq $class }).Count
    if ($count -gt 0) {
        Write-Host "    $count  $($classLabels[$class])"
    }
}

$activeCount = @($allResults | Where-Object { $_.classification -eq "ACTIVE" }).Count
$unknownCount = @($allResults | Where-Object { $_.classification -in @("UNKNOWN", "PENDING") }).Count
if ($activeCount -gt 0) { Write-Host "    $activeCount  Active (traffic confirmed via Azure Monitor)" }
if ($unknownCount -gt 0) { Write-Host "    $unknownCount  Unknown / recently pending (insufficient data)" }

Write-Host ""

if (-not $CheckAzure) {
    Write-Host "Tip: Re-run with -CheckAzure to query Azure Monitor Transactions metrics"
    Write-Host "     on each storage account for more accurate traffic detection."
    Write-Host ""
}

# --- Delete mode ---

if ($Delete -and $flaggedRules -gt 0) {
    Write-Host ""
    Write-Host "DELETE MODE: Review flagged rules for deletion"
    Write-Host ("-" * 60)

    foreach ($entry in ($allResults | Where-Object { $_.flagged })) {
        Write-Host ""
        Write-Host "  Rule:           $($entry.rule_id)"
        Write-Host "  Resource:       $($entry.resource_short) ($($entry.group_id))"
        Write-Host "  Classification: $($entry.classification)"
        Write-Host "  Full resource:  $($entry.resource_id)"
        if ($entry.transactions) {
            Write-Host "  Transactions:   $(Format-Number -Value ([long]$entry.transactions))"
        }

        $confirm = Read-Host "  Delete this rule? [y/N]"
        if ($confirm -match "^[Yy]$") {
            Write-Host "  Deleting..."
            try {
                databricks account network-connectivity delete-private-endpoint-rule $entry.ncc_id $entry.rule_id 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  Done. Rule will be deactivated."
                }
                else {
                    Write-Host "  ERROR: Failed to delete rule."
                }
            }
            catch {
                Write-Host "  ERROR: Failed to delete rule. $_"
            }
        }
        else {
            Write-Host "  Skipped."
        }
    }
}
