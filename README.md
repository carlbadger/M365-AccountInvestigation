# M365 Compromise Investigation Toolkit

Repeatable PowerShell-based forensic investigation script for suspected M365 account compromises.

---

## What It Does

Runs the following in sequence against a target account:

1. **Inbox rules** — checks for active forwarding, redirect, or auto-delete rules
2. **Mailbox delegation** — checks for FullAccess and SendAs grants
3. **UAL: Mail operations** — sends, deletes, rule changes, permission changes
4. **UAL: MailItemsAccessed** — per-message mailbox read activity with AppId resolution
5. **UAL: SharePoint** — file access, downloads, sync, anonymous link creation
6. **UAL: Azure AD / OAuth** — consent grants, app permissions, user modifications
7. **UAL: Full catch-all** — complete audit log export for the window
8. **Entra sign-in logs** — interactive sign-ins with risk level (via Graph)

Outputs a timestamped report folder containing:
- CSV exports for each surface
- A markdown summary with findings, severity flags, and an investigation conclusion

---

## Requirements

### Modules
```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

Minimal Graph install (faster, recommended):
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Reports -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
```

> **Note:** Do not load ExchangeOnlineManagement and Microsoft.Graph in the same PowerShell 5.1 session — MSAL assembly conflicts will cause Graph authentication to fail. Either use separate sessions, or run everything in PowerShell 7 (pwsh) which maintains separate module paths.

### Permissions Required (Admin Account)

| Surface | Role / Scope |
|---------|-------------|
| Exchange Online | `Compliance Management` or `View-Only Audit Logs` |
| Microsoft Graph | `AuditLog.Read.All`, `Directory.Read.All` |

---

## Usage

### Basic
```powershell
.\Invoke-CompromiseInvestigation.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -AdminUPN "admin@contoso.com" `
    -StartDate "01/06/2025" `
    -EndDate "01/10/2025"
```

### Skip Graph (Exchange only — no Entra sign-in logs)
```powershell
.\Invoke-CompromiseInvestigation.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -AdminUPN "admin@contoso.com" `
    -StartDate "01/06/2025" `
    -SkipGraphConnect
```

### Custom output path
```powershell
.\Invoke-CompromiseInvestigation.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -AdminUPN "admin@contoso.com" `
    -StartDate "01/06/2025" `
    -OutputPath "C:\Investigations"
```

> Date format must be `MM/DD/YYYY`. EndDate defaults to today if not specified.

---

## Output Structure

```
Investigation_jsmith_contoso_com_20250110_143022/
├── 00_Summary.md                  <- Start here. Findings + conclusion.
├── 01_InboxRules.csv              <- Active rules at time of investigation
├── 02_MailboxPermissions.csv      <- FullAccess delegation
├── 02_SendAsPermissions.csv       <- SendAs delegation
├── 03_UAL_Mail.csv                <- Send, delete, rule change operations
├── 03b_MailItemsAccessed.csv      <- Per-message read activity (if available)
├── 04_UAL_SharePoint.csv          <- File access, downloads, sharing events
├── 05_UAL_AAD.csv                 <- OAuth consent grants, app permissions
├── 06_UAL_Full.csv                <- Full UAL export — all operations in window
└── 07_EntraSignIns.csv            <- Entra interactive sign-in log
```

---

## Severity Levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Active exfil indicator, persistence mechanism, or unrecognized app access — escalate immediately |
| `WARNING` | Anomalous activity requiring review before closing |
| `INFO` | Clean result or informational — no action required |

---

## MailItemsAccessed Detail (03b)

`MailItemsAccessed` records when a mail client or application reads message content. The script flattens these into one row per message with the following fields:

| Field | Description |
|-------|-------------|
| `CreationTime` | When the access occurred |
| `ClientIP` | IP address of the accessing client or service |
| `AppId` | Application GUID that performed the access |
| `ClientInfo` | Raw client string (e.g. `Client=REST;Client=RESTSystem`) |
| `ExternalAccess` | True if access originated from outside the tenant |
| `AccessType` | `Bind` = specific messages accessed / `Sync` = bulk folder pull |
| `FolderPath` | Mailbox folder path (e.g. `\Inbox`, `\Archive\HR & Recruiting`) |
| `Subject` | Email subject line |
| `SizeKB` | Message size in KB |
| `MessageId` | Internet Message ID for cross-referencing |

### AppId Resolution

The script automatically resolves unknown AppIds via Graph and flags anything not in the known Microsoft first-party list. Resolution logic:

- Checks `AppOwnerOrganizationId` against Microsoft's tenant ID (`f8cdef31-a31e-4b4a-93e4-5f571e91255a`)
- Logs `INFO` for confirmed Microsoft-owned apps
- Logs `CRITICAL` for third-party or unresolvable AppIds

To extend the known Microsoft AppId list, add entries to the `$knownMsftAppIds` array in the script. Cross-reference unknown AppIds at:
```
https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json
```

---

## Known Limitations

| Limitation | Detail |
|------------|--------|
| **UAL retention** | 90 days on E3. Investigations beyond this window return no data. |
| **Graph sign-in retention** | 30 days interactive / 30 days non-interactive. Entra P1/P2 extends this. |
| **PS5.1 module conflicts** | ExchangeOnlineManagement and Microsoft.Graph conflict in the same session. Use PowerShell 7 or separate sessions. |
| **UAL pagination** | Handled automatically via `ReturnLargeSet`. Accounts with very high mail volume may take several minutes per pull. |
| **Read-only** | Script performs no modifications. Remediation (account suspension, token revocation, password reset) must be completed separately before running. |

---

## Adapting for Portfolio Companies

- Maintain a dedicated IR admin account per tenant with appropriate Exchange and Graph roles — avoid using personal admin UPNs
- Store this script in a shared IR runbook repo alongside incident response templates
- The `$knownMsftAppIds` array should be treated as a living list — update it as you encounter legitimate first-party AppIds across tenants
- For tenants on E3, include the MailItemsAccessed licensing gap explicitly in every incident record where mailbox access is confirmed

---

## Disclaimer

This script performs read-only forensic queries. It does not modify any account, mailbox, permission, or configuration state.
Account remediation (suspension, session token revocation, password reset) should be completed prior to running this investigation.
