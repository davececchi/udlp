#!/usr/bin/env bash
set -euo pipefail

# Audit NCC private endpoint rules to find unused/stale endpoints.
#
# Classification signals:
#   1. connection_state: REJECTED/DISCONNECTED/EXPIRED = definitively unused
#   2. Azure Monitor: Transactions metric on target storage accounts (--check-azure)
#   3. Age: PENDING rules older than threshold were never approved
#
# Requires: databricks CLI (account-level auth), jq
# Optional: az CLI (for --check-azure)

DAYS=60
NCC_ID=""
ALL_NCCS=false
CHECK_AZURE=false
OUTPUT_FORMAT="table"
DELETE_MODE=false

usage() {
  cat <<EOF
Audit NCC private endpoint rules for unused endpoints.

Usage:
  $0                          Interactive NCC selection
  $0 --ncc-id <id>            Audit a specific NCC
  $0 --all                    Audit all NCCs in the account

Options:
  --ncc-id <id>     Audit a specific NCC
  --all             Audit all NCCs in the account
  --days <n>        Days of inactivity to flag (default: 60)
  --check-azure     Query Azure Monitor Transactions metric on storage accounts (requires az CLI)
  --json            Output results as JSON
  --delete          Interactively prompt to delete flagged rules
  --help            Show this help

Classifications:
  DEAD:REJECTED      Connection was rejected by the resource owner
  DEAD:DISCONNECTED  Connection was disconnected
  DEAD:EXPIRED       Connection expired
  STALE_PENDING      Pending for >${DAYS} days, never approved
  NO_TRAFFIC         Zero Azure Monitor transactions in ${DAYS} days
  LIKELY_UNUSED      No config change in ${DAYS} days (no Azure data available)
  DEACTIVATED        Already marked for deletion
  ACTIVE             Azure Monitor confirmed traffic
  PENDING            Recently created, still awaiting approval
  UNKNOWN            Insufficient data to classify
EOF
  exit 0
}

# --- Preflight ---

check_prereqs() {
  if ! command -v databricks &>/dev/null; then
    echo "Error: databricks CLI not found. Install from https://docs.databricks.com/dev-tools/cli" >&2
    exit 1
  fi
  if ! command -v jq &>/dev/null; then
    echo "Error: jq not found. Install with: brew install jq" >&2
    exit 1
  fi
  if [[ "$CHECK_AZURE" == true ]] && ! command -v az &>/dev/null; then
    echo "Error: --check-azure requires the Azure CLI (az). Install from https://aka.ms/installazurecli" >&2
    exit 1
  fi
}

# --- Arg parsing ---

while [[ $# -gt 0 ]]; do
  case $1 in
    --ncc-id)       NCC_ID="$2"; shift 2 ;;
    --all)          ALL_NCCS=true; shift ;;
    --days)         DAYS="$2"; shift 2 ;;
    --check-azure)  CHECK_AZURE=true; shift ;;
    --json)         OUTPUT_FORMAT="json"; shift ;;
    --delete)       DELETE_MODE=true; shift ;;
    --help)         usage ;;
    *)              echo "Unknown option: $1" >&2; usage ;;
  esac
done

check_prereqs

# Compute cutoff timestamp in ms (macOS date vs GNU date)
if date -v-1d +%s &>/dev/null; then
  CUTOFF_EPOCH=$(date -v-${DAYS}d +%s)
else
  CUTOFF_EPOCH=$(date -d "-${DAYS} days" +%s)
fi
CUTOFF_MS=$((CUTOFF_EPOCH * 1000))

# --- Helpers ---

log() { [[ "$OUTPUT_FORMAT" == "table" ]] && echo "$@" || true; }

fetch_ncc_list() {
  local result
  result=$(databricks account network-connectivity list-network-connectivity-configurations --output json 2>&1) || {
    echo "Error: Failed to list NCCs. Ensure Databricks CLI has account-level auth configured." >&2
    echo "  export DATABRICKS_HOST=https://accounts.azuredatabricks.net  (or accounts.cloud.databricks.com)" >&2
    echo "  export DATABRICKS_ACCOUNT_ID=<your-account-id>" >&2
    exit 1
  }
  echo "$result"
}

select_ncc_interactive() {
  local ncc_list="$1"
  local ncc_count
  ncc_count=$(echo "$ncc_list" | jq length)

  if [[ "$ncc_count" -eq 0 ]]; then
    echo "Error: No NCCs found in this account." >&2
    exit 1
  fi

  echo "" >&2
  echo "Available NCCs:" >&2
  echo "---" >&2
  for i in $(seq 0 $((ncc_count - 1))); do
    local name region id
    name=$(echo "$ncc_list" | jq -r ".[$i].name // \"unnamed\"")
    id=$(echo "$ncc_list" | jq -r ".[$i].network_connectivity_config_id")
    region=$(echo "$ncc_list" | jq -r ".[$i].region // \"unknown\"")
    echo "  [$((i + 1))] $name ($region) - $id" >&2
  done
  echo "" >&2

  read -rp "Select an NCC [1-$ncc_count]: " selection
  if ! [[ "$selection" =~ ^[0-9]+$ ]] || [[ "$selection" -lt 1 ]] || [[ "$selection" -gt "$ncc_count" ]]; then
    echo "Error: Invalid selection" >&2
    exit 1
  fi

  echo "$ncc_list" | jq -r ".[$(( selection - 1 ))].network_connectivity_config_id"
}

# Format epoch-ms timestamp to YYYY-MM-DD
format_ts() {
  local ts_ms="$1"
  if [[ "$ts_ms" -le 0 ]]; then
    echo "N/A"
    return
  fi
  local ts_s=$((ts_ms / 1000))
  date -r "$ts_s" "+%Y-%m-%d" 2>/dev/null || date -d "@$ts_s" "+%Y-%m-%d" 2>/dev/null || echo "N/A"
}

# Extract short name from Azure resource ID (last segment)
short_name() {
  echo "$1" | awk -F/ '{print $NF}'
}

# Query Azure Monitor for storage account Transactions over the lookback window.
# Returns: "<status>:<count>" where status is true/false/skipped/unknown and count is the transaction total.
# Examples: "true:148293", "false:0", "skipped:", "unknown:"
AZURE_TXNS=""  # global: raw transaction count from last check_azure_traffic call
check_azure_traffic() {
  local resource_id="$1"
  AZURE_TXNS=""

  if [[ "$CHECK_AZURE" != true ]]; then
    echo "skipped"
    return
  fi

  # Only storage accounts supported for now
  case "$resource_id" in
    */Microsoft.Storage/storageAccounts/*) ;;
    *)
      echo "unknown"
      return
      ;;
  esac

  local start_time end_time
  if date -v-1d +%s &>/dev/null; then
    start_time=$(date -u -v-${DAYS}d +"%Y-%m-%dT00:00:00Z")
  else
    start_time=$(date -u -d "-${DAYS} days" +"%Y-%m-%dT00:00:00Z")
  fi
  end_time=$(date -u +"%Y-%m-%dT23:59:59Z")

  local result
  result=$(az monitor metrics list \
    --resource "$resource_id" \
    --metric "Transactions" \
    --aggregation Total \
    --start-time "$start_time" \
    --end-time "$end_time" \
    --interval P1D \
    --output json 2>/dev/null) || {
    echo "unknown"
    return
  }

  local total
  total=$(echo "$result" | jq '[.value[0].timeseries[]?.data[]?.total // 0] | add // 0' 2>/dev/null)
  # Normalize to integer
  total=$(printf "%.0f" "$total" 2>/dev/null || echo "0")
  AZURE_TXNS="$total"

  if [[ "$total" -gt 0 ]] 2>/dev/null; then
    echo "true"
  else
    echo "false"
  fi
}

# Format a large number with commas: 1234567 -> 1,234,567
format_number() {
  local n="$1"
  if [[ -z "$n" || "$n" == "0" ]]; then
    echo "0"
    return
  fi
  # Use printf with locale if available, fall back to sed
  LC_NUMERIC=en_US printf "%'.0f" "$n" 2>/dev/null || echo "$n" | sed ':a;s/\B[0-9]\{3\}\>$/,&/;ta'
}

# --- Main ---

ncc_ids=()

if [[ -n "$NCC_ID" ]]; then
  ncc_ids+=("$NCC_ID")
elif [[ "$ALL_NCCS" == true ]]; then
  log "Fetching all NCCs..."
  ncc_list=$(fetch_ncc_list)
  while IFS= read -r id; do
    ncc_ids+=("$id")
  done < <(echo "$ncc_list" | jq -r '.[].network_connectivity_config_id')
  log "Found ${#ncc_ids[@]} NCC(s)"
else
  ncc_list=$(fetch_ncc_list)
  NCC_ID=$(select_ncc_interactive "$ncc_list")
  ncc_ids+=("$NCC_ID")
fi

all_results="[]"
total_rules=0
flagged_rules=0

for ncc_id in "${ncc_ids[@]}"; do
  log ""
  log "Auditing NCC: $ncc_id"
  log "$(printf '=%.0s' {1..60})"

  rules=$(databricks account network-connectivity list-private-endpoint-rules "$ncc_id" --output json 2>&1) || {
    log "  Warning: Failed to list rules for NCC $ncc_id: $rules"
    continue
  }

  rule_count=$(echo "$rules" | jq 'length')
  if [[ "$rule_count" -eq 0 ]]; then
    log "  No private endpoint rules found."
    continue
  fi

  log "  Found $rule_count rule(s). Analyzing..."
  [[ "$CHECK_AZURE" == true ]] && log "  (Querying Azure Monitor for each storage account - this may take a moment)"
  log ""

  for i in $(seq 0 $((rule_count - 1))); do
    rule=$(echo "$rules" | jq ".[$i]")
    rule_id=$(echo "$rule" | jq -r '.rule_id')
    resource_id=$(echo "$rule" | jq -r '.resource_id // "N/A"')
    group_id=$(echo "$rule" | jq -r '.group_id // "N/A"')
    state=$(echo "$rule" | jq -r '.connection_state // "UNKNOWN"')
    creation_time=$(echo "$rule" | jq -r '.creation_time // 0')
    updated_time=$(echo "$rule" | jq -r '.updated_time // 0')
    deactivated=$(echo "$rule" | jq -r '.deactivated // false')

    # --- Classify inline (avoid subshell so AZURE_TXNS global propagates) ---
    classification=""
    AZURE_TXNS=""
    txns_display=""

    if [[ "$deactivated" == "true" ]]; then
      classification="DEACTIVATED"
    elif [[ "$state" == "REJECTED" || "$state" == "DISCONNECTED" || "$state" == "EXPIRED" ]]; then
      classification="DEAD:$state"
    elif [[ "$state" == "PENDING" ]]; then
      if [[ "$creation_time" -gt 0 && "$creation_time" -lt "$CUTOFF_MS" ]]; then
        classification="STALE_PENDING"
      else
        classification="PENDING"
      fi
    else
      # ESTABLISHED - check Azure metrics (writes to AZURE_TXNS global)
      check_azure_traffic "$resource_id" > /tmp/_ncc_audit_az_result
      azure_traffic=$(cat /tmp/_ncc_audit_az_result)
      case "$azure_traffic" in
        false)  classification="NO_TRAFFIC" ;;
        true)   classification="ACTIVE" ;;
        *)
          if [[ "$updated_time" -gt 0 && "$updated_time" -lt "$CUTOFF_MS" ]]; then
            classification="LIKELY_UNUSED"
          else
            classification="UNKNOWN"
          fi
          ;;
      esac
    fi

    # Format transaction count for display
    if [[ -n "$AZURE_TXNS" ]]; then
      txns_display=$(format_number "$AZURE_TXNS")
    fi

    flagged=false
    case "$classification" in
      DEAD:*|STALE_PENDING|NO_TRAFFIC|DEACTIVATED|LIKELY_UNUSED)
        flagged=true
        ;;
    esac

    total_rules=$((total_rules + 1))
    [[ "$flagged" == true ]] && flagged_rules=$((flagged_rules + 1))

    created_str=$(format_ts "$creation_time")
    updated_str=$(format_ts "$updated_time")
    resource_short=$(short_name "$resource_id")

    result=$(jq -n \
      --arg ncc_id "$ncc_id" \
      --arg rule_id "$rule_id" \
      --arg resource_id "$resource_id" \
      --arg resource_short "$resource_short" \
      --arg group_id "$group_id" \
      --arg state "$state" \
      --arg classification "$classification" \
      --argjson flagged "$flagged" \
      --arg created "$created_str" \
      --arg updated "$updated_str" \
      --arg transactions "${AZURE_TXNS:-}" \
      '{ncc_id: $ncc_id, rule_id: $rule_id, resource_id: $resource_id, resource_short: $resource_short, group_id: $group_id, state: $state, classification: $classification, flagged: $flagged, created: $created, updated: $updated, transactions: $transactions}')

    all_results=$(echo "$all_results" | jq --argjson r "$result" '. + [$r]')

    if [[ "$OUTPUT_FORMAT" == "table" ]]; then
      if [[ "$flagged" == true ]]; then
        icon="!!"
      else
        icon="ok"
      fi
      printf "  [%s] %-25s %-8s %-16s  Created: %s  Updated: %s\n" \
        "$icon" "$resource_short" "$group_id" "$classification" "$created_str" "$updated_str"
      printf "        Rule: %s\n" "$rule_id"
      printf "        Resource: %s\n" "$resource_id"
      if [[ -n "$txns_display" ]]; then
        printf "        Transactions (%sd): %s\n" "$DAYS" "$txns_display"
      fi
      printf "\n"
    fi
  done
done

# --- Summary ---

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  echo "$all_results" | jq '{
    summary: {
      total_rules: (. | length),
      flagged_rules: ([.[] | select(.flagged)] | length),
      by_classification: (group_by(.classification) | map({(.[0].classification): length}) | add // {})
    },
    flagged: [.[] | select(.flagged)],
    all_rules: .
  }'
  exit 0
fi

log ""
log "$(printf '=%.0s' {1..60})"
log "AUDIT SUMMARY (${DAYS}-day lookback)"
log "$(printf '=%.0s' {1..60})"
log "  Total rules scanned:  $total_rules"
log "  Flagged for review:   $flagged_rules"
log ""

for class in DEAD:REJECTED DEAD:DISCONNECTED DEAD:EXPIRED STALE_PENDING NO_TRAFFIC LIKELY_UNUSED DEACTIVATED; do
  count=$(echo "$all_results" | jq --arg c "$class" '[.[] | select(.classification == $c)] | length')
  if [[ "$count" -gt 0 ]]; then
    case "$class" in
      DEAD:REJECTED)     label="Rejected (never approved by resource owner)" ;;
      DEAD:DISCONNECTED) label="Disconnected" ;;
      DEAD:EXPIRED)      label="Expired" ;;
      STALE_PENDING)     label="Pending > ${DAYS} days (never approved)" ;;
      NO_TRAFFIC)        label="Zero transactions on storage account (${DAYS}d)" ;;
      LIKELY_UNUSED)     label="Likely unused (no config change in ${DAYS}d, no Azure data)" ;;
      DEACTIVATED)       label="Already deactivated (pending deletion)" ;;
    esac
    log "    $count  $label"
  fi
done

active_count=$(echo "$all_results" | jq '[.[] | select(.classification == "ACTIVE")] | length')
unknown_count=$(echo "$all_results" | jq '[.[] | select(.classification == "UNKNOWN" or .classification == "PENDING")] | length')
[[ "$active_count" -gt 0 ]] && log "    $active_count  Active (traffic confirmed via Azure Monitor)"
[[ "$unknown_count" -gt 0 ]] && log "    $unknown_count  Unknown / recently pending (insufficient data)"

log ""

if [[ "$CHECK_AZURE" != true ]]; then
  log "Tip: Re-run with --check-azure to query Azure Monitor Transactions metrics"
  log "     on each storage account for more accurate traffic detection."
  log ""
fi

# --- Delete mode ---

if [[ "$DELETE_MODE" == true && "$flagged_rules" -gt 0 ]]; then
  log ""
  log "DELETE MODE: Review flagged rules for deletion"
  log "$(printf -- '-%.0s' {1..60})"

  echo "$all_results" | jq -c '.[] | select(.flagged)' | while IFS= read -r entry; do
    r_id=$(echo "$entry" | jq -r '.rule_id')
    n_id=$(echo "$entry" | jq -r '.ncc_id')
    r_short=$(echo "$entry" | jq -r '.resource_short')
    g_id=$(echo "$entry" | jq -r '.group_id')
    cls=$(echo "$entry" | jq -r '.classification')
    r_full=$(echo "$entry" | jq -r '.resource_id')

    echo ""
    echo "  Rule:           $r_id"
    echo "  Resource:       $r_short ($g_id)"
    echo "  Classification: $cls"
    echo "  Full resource:  $r_full"

    read -rp "  Delete this rule? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
      echo "  Deleting..."
      if databricks account network-connectivity delete-private-endpoint-rule "$n_id" "$r_id" 2>&1; then
        echo "  Done. Rule will be deactivated."
      else
        echo "  ERROR: Failed to delete rule."
      fi
    else
      echo "  Skipped."
    fi
  done
fi
