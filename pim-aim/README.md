# PIM / AIM membership diagnostic

Checks whether **Azure PIM** (Entra) and **Databricks AIM** agree about a
single user's membership in a single group. Use it when a user appears to
have elevated Databricks access that their PIM assignment shouldn't grant
(e.g. the assignment is *eligible* but not *active*).

It collects ground truth from both sides into one JSON file and prints a
short interpretation.

Two equivalent versions — use whichever fits your shell:

- `diagnose-pim-aim.sh` — Bash / macOS / Linux
- `Diagnose-PimAim.ps1` — PowerShell 7+ / Windows

## Pre-reqs (do these first)

1. **Tools installed and on PATH:**
   - `az` (Azure CLI)
   - `databricks` (Databricks CLI, v0.220+)
   - Bash version also needs `jq` (and `curl` only if you use `--graph-token`)
   - PowerShell version needs PowerShell 7+

2. **Sign in to Azure:**

   ```
   az login --tenant <tenant-id>
   ```

3. **Sign in to the Databricks _account_ (not a workspace):**

   ```
   databricks auth login --host https://accounts.azuredatabricks.net --account-id <account-id>
   ```

   The signed-in identity must be a **Databricks account admin**, and the
   `--account-id` you pass to the script (below) must match the account you
   logged into here.

4. **Optional — to read PIM eligibility data:** the Azure CLI token can't
   read PIM-for-Groups, so those steps fail unless you supply a Microsoft
   Graph token that has these scopes:
   `PrivilegedAccess.Read.AzureADGroup`,
   `PrivilegedEligibilitySchedule.Read.AzureADGroup`,
   `PrivilegedAssignmentSchedule.Read.AzureADGroup`. Mint one (e.g. with
   `Connect-MgGraph -Scopes ...`) and pass it via `--graph-token` /
   `$GRAPH_TOKEN`. Without it the rest of the report still runs.

## How to run

Bash:

```
./diagnose-pim-aim.sh \
  --user <user@domain.com> \
  --group <entra-group-object-id> \
  --account-id <databricks-account-id>
```

PowerShell:

```
./Diagnose-PimAim.ps1 `
  -User <user@domain.com> `
  -GroupId <entra-group-object-id> `
  -AccountId <databricks-account-id>
```

Add `--graph-token <jwt>` (Bash) or `-GraphToken <jwt>` (PowerShell) to
include PIM eligibility data.

Run with `--help` (Bash) or `Get-Help ./Diagnose-PimAim.ps1 -Full`
(PowerShell) for all options.

## Output

A summary is printed to the console, and the full bundle is saved to
`pim-aim-diag-<timestamp>.json`. Attach that file when escalating to
Databricks support. A `null` section in the JSON usually means a call was
denied (see the `errors` array), not that the data is genuinely empty.
