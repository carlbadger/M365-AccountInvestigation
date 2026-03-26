#Requires -Modules ExchangeOnlineManagement
<#
.SYNOPSIS
    M365 Account Compromise Investigation Script

.DESCRIPTION
    Runs a structured forensic investigation against a suspected compromised M365 account.
    Pulls UAL (mail, SharePoint, AAD), inbox rules, mailbox delegation, and generates
    a timestamped report folder with CSV exports and a summary markdown file.

.PARAMETER UserPrincipalName
    The UPN of the suspected compromised account (e.g. user@domain.com)

.PARAMETER AdminUPN
    The UPN of the admin account used to connect to Exchange Online

.PARAMETER StartDate
    Investigation window start date (MM/DD/YYYY)

.PARAMETER EndDate
    Investigation window end date (MM/DD/YYYY). Defaults to today.

.PARAMETER OutputPath
    Root path where the report folder will be created. Defaults to current directory.

.PARAMETER SkipGraphConnect
    Switch to skip Microsoft Graph connection (skips Entra sign-in log pull)

.EXAMPLE
    .\Invoke-CompromiseInvestigation.ps1 `
        -UserPrincipalName "jsmith@contoso.com" `
        -AdminUPN "admin@contoso.com" `
        -StartDate "01/06/2025" `
        -EndDate "01/10/2025"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [string]$AdminUPN,

    [Parameter(Mandatory)]
    [string]$StartDate,

    [string]$EndDate = (Get-Date -Format "MM/dd/yyyy"),

    [string]$OutputPath = ".",

    [switch]$SkipGraphConnect
)

# NOTE: Do NOT enable Set-StrictMode — it breaks .Count on $null in PS5.1
$ErrorActionPreference = "Stop"

#region --- Helpers ---

$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$safeUser     = $UserPrincipalName -replace '[^a-zA-Z0-9]', '_'
$reportFolder = Join-Path $OutputPath "Investigation_${safeUser}_${timestamp}"
$summaryFile  = Join-Path $reportFolder "00_Summary.md"
$findings     = [System.Collections.Generic.List[string]]::new()

New-Item -ItemType Directory -Path $reportFolder -Force | Out-Null

function Write-Step {
    param([string]$Message)
    Write-Host "`n[*] $Message" -ForegroundColor Cyan
}

function Write-Finding {
    param([string]$Severity, [string]$Message)
    $line  = "[$Severity] $Message"
    $findings.Add($line)
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING"  { "Yellow" }
        "INFO"     { "Green" }
        default    { "White" }
    }
    Write-Host "    --> $line" -ForegroundColor $color
}

function Export-Results {
    param(
        [object[]]$Data,
        [string]$FileName,
        [string[]]$Props
    )
    $path = Join-Path $reportFolder $FileName
    $arr  = @($Data)
    if ($arr.Count -gt 0) {
        $arr | Select-Object $Props | Export-Csv $path -NoTypeInformation
        Write-Host "    Exported $($arr.Count) records -> $FileName" -ForegroundColor DarkGray
    } else {
        "No results" | Out-File $path
        Write-Host "    No results -> $FileName" -ForegroundColor DarkGray
    }
}

function Invoke-UALSearch {
    param(
        [string]$RecordType,
        [string[]]$Operations,
        [string]$Label
    )
    Write-Step "UAL Pull: $Label"

    $collected = [System.Collections.Generic.List[object]]::new()
    $sessionId = "Inv_${safeUser}_${Label}_${timestamp}"
    $page      = 1

    do {
        $params = @{
            UserIds        = $UserPrincipalName
            StartDate      = $StartDate
            EndDate        = $EndDate
            ResultSize     = 5000
            SessionId      = $sessionId
            SessionCommand = "ReturnLargeSet"
        }
        if ($RecordType) { $params.RecordType = $RecordType }

        $batch = $null
        try { $batch = Search-UnifiedAuditLog @params } catch {}
        if (-not $batch) { break }

        # Iterate individually — avoids PS5.1 pipeline collapsing single result to PSObject
        foreach ($record in $batch) {
            try {
                $parsed = $record.AuditData | ConvertFrom-Json
                if (-not $Operations -or ($parsed.Operation -in $Operations)) {
                    $collected.Add($parsed)
                }
            } catch {}
        }

        Write-Host "    Page $page — $($batch.Count) raw, $($collected.Count) matched" -ForegroundColor DarkGray
        $page++

    } while ($batch.Count -eq 5000)

    # Cast to object[] so callers always get a typed array, never $null
    return ,[object[]]$collected.ToArray()
}

#endregion

#region --- Connect ---

Write-Step "Connecting to Exchange Online"
try {
    Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false
    Write-Finding "INFO" "Exchange Online connection established"
} catch {
    Write-Error "Failed to connect to Exchange Online: $_"
    exit 1
}

if (-not $SkipGraphConnect) {
    Write-Step "Connecting to Microsoft Graph"
    try {
        Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -NoWelcome
        Write-Finding "INFO" "Microsoft Graph connection established"
    } catch {
        Write-Warning "Graph connection failed — skipping Entra sign-in log pull."
        $SkipGraphConnect = $true
    }
}

#endregion

#region --- Step 1: Inbox Rules ---

Write-Step "Checking current inbox rules"
try {
    $rules = @(Get-InboxRule -Mailbox $UserPrincipalName |
        Select-Object Name, Enabled, ForwardTo, ForwardAsAttachmentTo,
                      RedirectTo, DeleteMessage, MoveToFolder, StopProcessingRules)

    Export-Results -Data $rules -FileName "01_InboxRules.csv" `
        -Props Name, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder

    $suspicious = @($rules | Where-Object {
        $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
    })

    if ($suspicious.Count -gt 0) {
        Write-Finding "CRITICAL" "$($suspicious.Count) suspicious inbox rule(s) — forwarding or auto-delete present"
        foreach ($r in $suspicious) {
            Write-Finding "CRITICAL" "  Rule: '$($r.Name)' | Forward: $($r.ForwardTo) | Delete: $($r.DeleteMessage)"
        }
    } else {
        Write-Finding "INFO" "No suspicious inbox rules found"
    }
} catch {
    Write-Finding "WARNING" "Could not retrieve inbox rules: $_"
}

#endregion

#region --- Step 2: Mailbox Delegation ---

Write-Step "Checking mailbox delegation"
try {
    $perms = @(Get-MailboxPermission -Identity $UserPrincipalName |
        Where-Object { $_.User -notlike "NT AUTHORITY*" -and $_.User -notlike "S-1-5*" })

    $sendAs = @(Get-RecipientPermission -Identity $UserPrincipalName |
        Where-Object { $_.Trustee -notlike "NT AUTHORITY*" })

    Export-Results -Data $perms  -FileName "02_MailboxPermissions.csv" -Props User, AccessRights, IsInherited
    Export-Results -Data $sendAs -FileName "02_SendAsPermissions.csv"  -Props Trustee, AccessControlType, AccessRights

    $fullAccess = @($perms | Where-Object { $_.AccessRights -like "*FullAccess*" })
    if ($fullAccess.Count -gt 0) {
        Write-Finding "CRITICAL" "FullAccess delegation found — $($fullAccess.User -join ', ')"
    } else {
        Write-Finding "INFO" "No unexpected mailbox delegation found"
    }

    $sendAsAllow = @($sendAs | Where-Object { $_.AccessControlType -eq "Allow" })
    if ($sendAsAllow.Count -gt 0) {
        Write-Finding "WARNING" "SendAs permission granted to non-standard trustee"
    } else {
        Write-Finding "INFO" "No unexpected SendAs permissions found"
    }
} catch {
    Write-Finding "WARNING" "Could not retrieve mailbox permissions: $_"
}

#endregion

#region --- Step 3: UAL Mail ---

$mailOps = @(
    "Send","SendAs","SendOnBehalf",
    "HardDelete","MoveToDeletedItems",
    "New-InboxRule","Set-InboxRule","Remove-InboxRule","UpdateInboxRules",
    "AddMailboxPermission","AddFolderPermissions"
)

$mailResults = Invoke-UALSearch -RecordType "ExchangeItem" -Operations $mailOps -Label "Mail"

Export-Results -Data $mailResults -FileName "03_UAL_Mail.csv" `
    -Props CreationTime, Operation, ClientIP, UserAgent, ResultStatus

$sendCount = @($mailResults | Where-Object { $_.Operation -in @("Send","SendAs","SendOnBehalf") }).Count
if ($sendCount -gt 0) {
    Write-Finding "CRITICAL" "$sendCount outbound send operation(s) — verify ClientIP against known-good addresses"
} else {
    Write-Finding "INFO" "No outbound send operations found"
}

$ruleCount = @($mailResults | Where-Object { $_.Operation -match "InboxRule" }).Count
if ($ruleCount -gt 0) {
    Write-Finding "WARNING" "$ruleCount inbox rule change(s) in audit log"
} else {
    Write-Finding "INFO" "No inbox rule changes in audit log"
}

#endregion

#region --- Step 3b: MailItemsAccessed ---

# Known Microsoft first-party AppIds that legitimately access mailboxes
# (Search indexing, Viva, compliance services, substrate etc.)
$knownMsftAppIds = @(
    "00000002-0000-0ff1-ce00-000000000000", # Exchange Online
    "00000003-0000-0000-c000-000000000000", # Microsoft Graph
    "00000007-0000-0ff1-ce00-000000000000", # SharePoint Online
    "13937bba-652e-4c46-b222-3003f4d1ff97", # Microsoft substrate/search
    "00b41c95-dab0-4487-9791-b9d2c32c80f2", # Office 365 Management
    "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87", # Microsoft Forms
    "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", # Viva
    "ab9b8c07-8f02-4f72-87fa-80105867a763"  # OneDrive Sync
)

Write-Step "UAL Pull: MailItemsAccessed"

$miaRaw = $null
try {
    $miaRaw = Search-UnifiedAuditLog `
        -UserIds        $UserPrincipalName `
        -Operations     "MailItemsAccessed" `
        -StartDate      $StartDate `
        -EndDate        $EndDate `
        -ResultSize     5000 `
        -SessionId      "Inv_${safeUser}_MIA_${timestamp}" `
        -SessionCommand ReturnLargeSet
} catch {}

$miaFlat = [System.Collections.Generic.List[object]]::new()

if ($miaRaw) {
    foreach ($record in $miaRaw) {
        try {
            $r = $record.AuditData | ConvertFrom-Json
            $accessType = ($r.OperationProperties | Where-Object { $_.Name -eq "MailAccessType" }).Value
            foreach ($folder in $r.Folders) {
                foreach ($item in $folder.FolderItems) {
                    $miaFlat.Add([PSCustomObject]@{
                        CreationTime  = $r.CreationTime
                        ClientIP      = $r.ClientIPAddress
                        AppId         = $r.AppId
                        ClientInfo    = $r.ClientInfoString
                        ExternalAccess = $r.ExternalAccess
                        AccessType    = $accessType
                        FolderPath    = $folder.Path
                        Subject       = $item.Subject
                        SizeKB        = [math]::Round($item.SizeInBytes / 1024, 1)
                        MessageId     = $item.InternetMessageId
                    })
                }
            }
        } catch {}
    }
}

$miaArray = [object[]]$miaFlat.ToArray()
$miaPath  = Join-Path $reportFolder "03b_MailItemsAccessed.csv"

if ($miaArray.Count -gt 0) {
    $miaArray | Sort-Object CreationTime | Export-Csv $miaPath -NoTypeInformation
    Write-Host "    Exported $($miaArray.Count) message access record(s) -> 03b_MailItemsAccessed.csv" -ForegroundColor DarkGray

    # Flag any AppId not in the known Microsoft list
    $unknownApps = @($miaArray | Where-Object { $_.AppId -notin $knownMsftAppIds } | 
        Select-Object -ExpandProperty AppId -Unique)

    if ($unknownApps.Count -gt 0) {
        Write-Finding "CRITICAL" "MailItemsAccessed by unrecognized AppId(s): $($unknownApps -join ', ') — investigate immediately"
    } else {
        Write-Finding "INFO" "$($miaArray.Count) MailItemsAccessed event(s) — all attributed to known Microsoft services"
    }

    # Flag any external access
    $externalAccess = @($miaArray | Where-Object { $_.ExternalAccess -eq $true })
    if ($externalAccess.Count -gt 0) {
        Write-Finding "CRITICAL" "$($externalAccess.Count) MailItemsAccessed event(s) flagged ExternalAccess=true"
    }

    # Surface unique folders accessed for the summary
    $foldersAccessed = @($miaArray | Select-Object -ExpandProperty FolderPath -Unique)
    Write-Finding "INFO" "Folders accessed: $($foldersAccessed -join ' | ')"

} else {
    "No results" | Out-File $miaPath
    Write-Host "    No MailItemsAccessed events found -> 03b_MailItemsAccessed.csv" -ForegroundColor DarkGray
    Write-Finding "INFO" "No MailItemsAccessed events in window (E5/Compliance license may not be present)"
}

#endregion

#region --- Step 4: UAL SharePoint ---

$spOps = @(
    "FileDownloaded","FileAccessed","FileSyncDownloadedFull",
    "SharingInvitationCreated","AnonymousLinkCreated",
    "SiteCollectionAdminAdded","FileUploaded"
)

$spResults = Invoke-UALSearch -RecordType "SharePointFileOperation" -Operations $spOps -Label "SharePoint"

Export-Results -Data $spResults -FileName "04_UAL_SharePoint.csv" `
    -Props CreationTime, Operation, SiteUrl, SourceFileName, ClientIP, UserAgent

$spHighCount = @($spResults | Where-Object {
    $_.Operation -in @("AnonymousLinkCreated","SiteCollectionAdminAdded","FileSyncDownloadedFull")
}).Count
if ($spHighCount -gt 0) {
    Write-Finding "CRITICAL" "$spHighCount high-risk SharePoint operation(s) detected"
}

$dlCount = @($spResults | Where-Object { $_.Operation -eq "FileDownloaded" }).Count
if ($dlCount -gt 0) {
    Write-Finding "WARNING" "$dlCount SharePoint file download(s) detected"
} else {
    Write-Finding "INFO" "No SharePoint file downloads found"
}

$faCount = @($spResults | Where-Object { $_.Operation -eq "FileAccessed" }).Count
if ($faCount -gt 0) {
    Write-Finding "WARNING" "$faCount SharePoint file access event(s) — browser view, no download required"
} else {
    Write-Finding "INFO" "No SharePoint file access events found"
}

#endregion

#region --- Step 5: UAL AAD / OAuth ---

$aadOps = @(
    "Consent to application",
    "Add OAuth2PermissionGrant",
    "Update user",
    "Add service principal",
    "Update application"
)

$aadResults = Invoke-UALSearch -RecordType "AzureActiveDirectory" -Operations $aadOps -Label "AAD"

Export-Results -Data $aadResults -FileName "05_UAL_AAD.csv" `
    -Props CreationTime, Operation, ClientIP, UserAgent, ResultStatus

$oauthCount = @($aadResults | Where-Object {
    $_.Operation -in @("Consent to application","Add OAuth2PermissionGrant")
}).Count
if ($oauthCount -gt 0) {
    Write-Finding "CRITICAL" "$oauthCount OAuth consent grant(s) — potential persistence mechanism"
} else {
    Write-Finding "INFO" "No OAuth consent grants found"
}

#endregion

#region --- Step 6: Full UAL Catch-All ---

Write-Step "UAL Pull: Full catch-all"

$allAudit  = [System.Collections.Generic.List[object]]::new()
$sessionId = "Inv_${safeUser}_Full_${timestamp}"
$page      = 1

do {
    $batch = $null
    try {
        $batch = Search-UnifiedAuditLog `
            -UserIds        $UserPrincipalName `
            -StartDate      $StartDate `
            -EndDate        $EndDate `
            -ResultSize     5000 `
            -SessionId      $sessionId `
            -SessionCommand ReturnLargeSet
    } catch {}

    if (-not $batch) { break }

    foreach ($record in $batch) {
        try {
            $parsed = $record.AuditData | ConvertFrom-Json
            $allAudit.Add($parsed)
        } catch {}
    }

    Write-Host "    Page $page — $($allAudit.Count) total" -ForegroundColor DarkGray
    $page++

} while ($batch.Count -eq 5000)

$fullPath = Join-Path $reportFolder "06_UAL_Full.csv"
if ($allAudit.Count -gt 0) {
    [object[]]$allAudit.ToArray() |
        Select-Object CreationTime, Operation, RecordType, ClientIP, UserAgent |
        Sort-Object CreationTime |
        Export-Csv $fullPath -NoTypeInformation
    Write-Host "    Exported $($allAudit.Count) records -> 06_UAL_Full.csv" -ForegroundColor DarkGray
} else {
    "No results" | Out-File $fullPath
    Write-Host "    No results -> 06_UAL_Full.csv" -ForegroundColor DarkGray
}

Write-Finding "INFO" "Full UAL export — $($allAudit.Count) total events in window"

#endregion

#region --- Step 7: Entra Sign-In Logs ---

if (-not $SkipGraphConnect) {
    Write-Step "Pulling Entra sign-in logs via Microsoft Graph"
    try {
        $filter  = "userPrincipalName eq '$UserPrincipalName'"
        $signIns = @(Get-MgAuditLogSignIn -Filter $filter -Top 500 |
            Select-Object CreatedDateTime, AppDisplayName, IpAddress,
                          ClientAppUsed, ConditionalAccessStatus,
                          RiskLevelDuringSignIn, RiskState, Status)

        Export-Results -Data $signIns -FileName "07_EntraSignIns.csv" `
            -Props CreatedDateTime, AppDisplayName, IpAddress, ClientAppUsed,
                   ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState

        $riskyCount = @($signIns | Where-Object {
            $_.RiskLevelDuringSignIn -notin @("none","")
        }).Count
        if ($riskyCount -gt 0) {
            Write-Finding "WARNING" "$riskyCount sign-in(s) flagged with elevated risk by Entra"
        } else {
            Write-Finding "INFO" "No elevated-risk sign-ins detected"
        }

        $failCount = @($signIns | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
        if ($failCount -gt 0) {
            Write-Finding "INFO" "$failCount failed sign-in attempt(s) in window"
        }

    } catch {
        Write-Finding "WARNING" "Could not retrieve Entra sign-in logs: $_"
    }
}

#endregion

#region --- Summary ---

Write-Step "Generating summary report"

$criticals = @($findings | Where-Object { $_ -match "\[CRITICAL\]" }).Count
$warnings  = @($findings | Where-Object { $_ -match "\[WARNING\]" }).Count

$conclusion = if ($criticals -gt 0) {
    "**Status: CRITICAL FINDINGS PRESENT — Review flagged items above before closing.**"
} elseif ($warnings -gt 0) {
    "**Status: WARNINGS present — No confirmed exfiltration but items require review.**"
} else {
    "**Status: No evidence of active exfiltration found within audit log coverage.**`n`n> Note: MailItemsAccessed unavailable without E5. Passive mailbox observation cannot be excluded. Document this gap in your incident record."
}

@"
# M365 Compromise Investigation Summary

**Target Account:** $UserPrincipalName
**Investigation Window:** $StartDate — $EndDate
**Report Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Investigator (Admin):** $AdminUPN

---

## Audit Limitations

> This tenant does not have E5 or M365 Compliance add-on licensing.
> **MailItemsAccessed** events are unavailable.
> Mailbox read activity cannot be confirmed or excluded — document this gap accordingly.

---

## Findings

$(($findings | ForEach-Object { "- $_" }) -join "`n")

---

## Exports

| File | Contents |
|------|----------|
| 01_InboxRules.csv | Active inbox rules at time of investigation |
| 02_MailboxPermissions.csv | Mailbox FullAccess delegation |
| 02_SendAsPermissions.csv | SendAs delegation |
| 03_UAL_Mail.csv | Mail send, delete, rule change operations |
| 03b_MailItemsAccessed.csv | Per-message mailbox read activity — folder, subject, AppId |
| 04_UAL_SharePoint.csv | SharePoint file access and download events |
| 05_UAL_AAD.csv | Azure AD / OAuth consent and app grant events |
| 06_UAL_Full.csv | Full UAL export — all operations in window |
| 07_EntraSignIns.csv | Entra interactive sign-in log |

---

## Conclusion

$conclusion
"@ | Out-File $summaryFile -Encoding UTF8

Write-Host "`n[+] Summary -> $summaryFile" -ForegroundColor Green

#endregion

#region --- Disconnect ---

Write-Step "Disconnecting"
try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
if (-not $SkipGraphConnect) { try { Disconnect-MgGraph | Out-Null } catch {} }

#endregion

Write-Host "`n============================================" -ForegroundColor Green
Write-Host " Investigation complete." -ForegroundColor Green
Write-Host " Report: $reportFolder" -ForegroundColor Green
Write-Host "============================================`n" -ForegroundColor Green
