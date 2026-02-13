param(
    [string]$SearchString,
    [switch]$ShowOverlaps,

    # CSV export
    [switch]$ExportCsv,
    [string]$ExportPath = "C:\TS-Temp"
)

$DomainName = $env:USERDNSDOMAIN

Import-Module GroupPolicy
Import-Module ActiveDirectory

function ConvertFrom-LinkOptions {
    param([int]$Option)
    $enabled  = ($Option -band 1) -eq 0
    $enforced = ($Option -band 2) -ne 0
    [PSCustomObject]@{ Enabled = $enabled; Enforced = $enforced }
}

function Get-GpoSecurityFiltering {
    param(
        [Parameter(Mandatory)]
        [Guid]$GpoGuid,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    $perms = Get-GPPermission -Guid $GpoGuid -Domain $Domain -All -ErrorAction Stop
    $apply = $perms | Where-Object { $_.Permission -eq "GpoApply" }

    $apply | ForEach-Object {
        $t = $_.Trustee
        if ($t.Domain -and $t.Name) { "$($t.Domain)\$($t.Name)" }
        elseif ($t.Name) { $t.Name }
        else { "[Unknown Trustee]" }
    } | Sort-Object -Unique
}

function Get-GpoLinkScopes {
    param(
        [Parameter(Mandatory)]
        [Guid]$GpoGuid
    )

    $guidText = $GpoGuid.ToString("B") # {GUID}

    $rootDse  = Get-ADRootDSE
    $domainDN = $rootDse.defaultNamingContext
    $configDN = $rootDse.configurationNamingContext

    $targets = @()

    # Domain + OU links
    $targets += Get-ADObject -LDAPFilter "(gPLink=*$guidText*)" `
        -SearchBase $domainDN -SearchScope Subtree `
        -Properties gPLink, distinguishedName, objectClass

    # Site links
    $sitesBase = "CN=Sites,$configDN"
    $targets += Get-ADObject -LDAPFilter "(gPLink=*$guidText*)" `
        -SearchBase $sitesBase -SearchScope Subtree `
        -Properties gPLink, distinguishedName, objectClass

    foreach ($t in $targets) {
        $m = [regex]::Match($t.gPLink, "\[LDAP://[^]]*cn=$([regex]::Escape($guidText))[^;]*;(\d+)\]")
        $opt = if ($m.Success) { [int]$m.Groups[1].Value } else { $null }
        $decoded = if ($null -ne $opt) { ConvertFrom-LinkOptions -Option $opt } else { $null }

        $scopeType =
            switch ($t.ObjectClass) {
                "domainDNS"          { "Domain" }
                "organizationalUnit" { "OU" }
                "site"               { "Site" }
                default              { $t.ObjectClass }
            }

        $friendlyName =
            if ($scopeType -eq "Domain") {
                $DomainName
            }
            elseif ($scopeType -eq "Site") {
                ($t.DistinguishedName -split ",")[0] -replace "^CN=", ""
            }
            else {
                $t.DistinguishedName
            }

        [PSCustomObject]@{
            ScopeType    = $scopeType
            ScopeName    = $friendlyName
            ScopeDN      = $t.DistinguishedName
            LinkEnabled  = if ($decoded) { $decoded.Enabled } else { $null }
            LinkEnforced = if ($decoded) { $decoded.Enforced } else { $null }
        }
    }
}

# Prep export folder if requested
if ($ExportCsv) {
    if (-not (Test-Path -Path $ExportPath)) {
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
    }
}

Write-Host "Finding all the GPOs in $DomainName"
$allGposInDomain = Get-GPO -All -Domain $DomainName | Sort-Object DisplayName

Write-Host "Starting search..."
$counter = 1

# Store match data (for overlaps and CSV)
$matchRecords = New-Object System.Collections.Generic.List[object]

foreach ($gpo in $allGposInDomain) {

    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    if ($report -match $SearchString) {

        Write-Host "********** Match found in: $counter. $($gpo.DisplayName) **********" -ForegroundColor Green

        # Linked scopes
        $scopes = Get-GpoLinkScopes -GpoGuid $gpo.Id | Sort-Object ScopeType, ScopeName

        if (-not $scopes -or $scopes.Count -eq 0) {
            Write-Host "  Linked scopes: (No links found)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  Linked scopes:"
            foreach ($s in $scopes) {
                $enabledText  = if ($null -ne $s.LinkEnabled)  { if ($s.LinkEnabled)  { "Enabled" } else { "Disabled" } } else { "Unknown" }
                $enforcedText = if ($null -ne $s.LinkEnforced) { if ($s.LinkEnforced) { "Enforced" } else { "Not enforced" } } else { "Unknown" }
                Write-Host ("   - {0}: {1} ({2}, {3})" -f $s.ScopeType, $s.ScopeName, $enabledText, $enforcedText)
            }
        }

        # Security filtering (Apply)
        $applyList = @()
        try {
            $applyList = Get-GpoSecurityFiltering -GpoGuid $gpo.Id -Domain $DomainName
            if (-not $applyList -or $applyList.Count -eq 0) {
                Write-Host "  Security filtering (Apply Group Policy): (None found)" -ForegroundColor Yellow
            }
            else {
                Write-Host "  Security filtering (Apply Group Policy):"
                $applyList | ForEach-Object { Write-Host "   - $_" }
            }
        }
        catch {
            Write-Host "  Security filtering: (Unable to read permissions: $($_.Exception.Message))" -ForegroundColor Yellow
        }

        # WMI filter
        $wmi = (Get-GPO -Guid $gpo.Id -Domain $DomainName).WmiFilter
        Write-Host ("  WMI filter: {0}" -f $(if ($wmi) { $wmi.Name } else { "(None)" }))
        Write-Host ""

        # Save match rows for later analysis/export
        if ($scopes -and $scopes.Count -gt 0) {
            foreach ($s in $scopes) {
                $matchRecords.Add([PSCustomObject]@{
                    SearchString            = $SearchString
                    GpoName                 = $gpo.DisplayName
                    GpoGuid                 = $gpo.Id
                    ScopeType               = $s.ScopeType
                    ScopeName               = $s.ScopeName
                    ScopeDN                 = $s.ScopeDN
                    LinkEnabled             = $s.LinkEnabled
                    LinkEnforced            = $s.LinkEnforced
                    SecurityFilteringApply  = ($applyList -join "; ")
                    WmiFilter               = if ($wmi) { $wmi.Name } else { "" }
                })
            }
        }
        else {
            $matchRecords.Add([PSCustomObject]@{
                SearchString            = $SearchString
                GpoName                 = $gpo.DisplayName
                GpoGuid                 = $gpo.Id
                ScopeType               = ""
                ScopeName               = ""
                ScopeDN                 = ""
                LinkEnabled             = $null
                LinkEnforced            = $null
                SecurityFilteringApply  = ($applyList -join "; ")
                WmiFilter               = if ($wmi) { $wmi.Name } else { "" }
            })
        }

    }
    else {
        Write-Host "$counter. No match in: $($gpo.DisplayName)"
    }

    $counter++
}

# Export matches to CSV (always useful)
if ($ExportCsv) {
    $matchesCsv = Join-Path $ExportPath "GpoMatches.csv"
    $matchRecords | Export-Csv $matchesCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported matches to: $matchesCsv" -ForegroundColor Cyan
}

# Overlap analysis
if ($ShowOverlaps) {

    Write-Host ""
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "OVERLAP ANALYSIS (Potential)" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""

    if ($matchRecords.Count -eq 0) {
        Write-Host "No matching GPOs found for '$SearchString', so no overlap to analyse." -ForegroundColor Yellow
        return
    }

    # 1) Same-scope overlap
    $sameScopeGroups = $matchRecords |
        Where-Object { $_.ScopeDN } |
        Group-Object ScopeType, ScopeDN |
        Where-Object { $_.Count -gt 1 } |
        Sort-Object Count -Descending

    $sameScopeOverlaps = foreach ($g in $sameScopeGroups) {
        foreach ($row in ($g.Group | Sort-Object GpoName)) {
            [PSCustomObject]@{
                ScopeType              = $row.ScopeType
                ScopeName              = $row.ScopeName
                ScopeDN                = $row.ScopeDN
                GpoName                = $row.GpoName
                LinkEnabled            = $row.LinkEnabled
                LinkEnforced           = $row.LinkEnforced
                SecurityFilteringApply = $row.SecurityFilteringApply
                WmiFilter              = $row.WmiFilter
            }
        }
    }

    if ($sameScopeGroups.Count -gt 0) {
        Write-Host "1) SAME-SCOPE OVERLAPS found: $($sameScopeGroups.Count)" -ForegroundColor Green
        if ($ExportCsv) {
            $sameCsv = Join-Path $ExportPath "SameScopeOverlaps.csv"
            $sameScopeOverlaps | Export-Csv $sameCsv -NoTypeInformation -Encoding UTF8
            Write-Host "Exported same-scope overlaps to: $sameCsv" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "1) SAME-SCOPE OVERLAPS: None found." -ForegroundColor Yellow
    }

    # 2) Hierarchy overlap (parent container + child OU)
    $hier = $matchRecords | Where-Object { $_.ScopeType -in @("Domain","OU") -and $_.ScopeDN }

    $hierOverlaps = New-Object System.Collections.Generic.List[object]

    foreach ($child in ($hier | Where-Object { $_.ScopeType -eq "OU" })) {
        foreach ($parent in $hier) {
            if ($parent.ScopeDN -ne $child.ScopeDN -and
                $child.ScopeDN.ToLower().EndsWith($parent.ScopeDN.ToLower())) {

                $hierOverlaps.Add([PSCustomObject]@{
                    ParentScopeType = $parent.ScopeType
                    ParentScopeName = $parent.ScopeName
                    ParentScopeDN   = $parent.ScopeDN
                    ParentGpoName   = $parent.GpoName
                    ParentEnforced  = $parent.LinkEnforced
                    ChildScopeType  = $child.ScopeType
                    ChildScopeName  = $child.ScopeName
                    ChildScopeDN    = $child.ScopeDN
                    ChildGpoName    = $child.GpoName
                    ChildEnforced   = $child.LinkEnforced
                })
            }
        }
    }

    if ($hierOverlaps.Count -gt 0) {
        Write-Host "2) HIERARCHY OVERLAPS found: $($hierOverlaps.Count)" -ForegroundColor Green
        if ($ExportCsv) {
            $hierCsv = Join-Path $ExportPath "HierarchyOverlaps.csv"
            $hierOverlaps | Export-Csv $hierCsv -NoTypeInformation -Encoding UTF8
            Write-Host "Exported hierarchy overlaps to: $hierCsv" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "2) HIERARCHY OVERLAPS: None found." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Note: This highlights potential overlap based on links. It does not compute effective application (block inheritance, link order, loopback, item-level targeting, etc.)." -ForegroundColor DarkYellow
}

# Summary
Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

$totalMatches = ($matchRecords | Select-Object -ExpandProperty GpoName -Unique).Count
$totalScopes  = ($matchRecords | Where-Object { $_.ScopeDN } | Select-Object -ExpandProperty ScopeDN -Unique).Count
$sameScopeCount = if ($sameScopeGroups) { $sameScopeGroups.Count } else { 0 }
$hierCount = if ($hierOverlaps) { $hierOverlaps.Count } else { 0 }

$summary = [PSCustomObject]@{
    SettingSearched      = $SearchString
    MatchingGPOs         = $totalMatches
    UniqueLinkedScopes   = $totalScopes
    SameScopeOverlaps    = $sameScopeCount
    HierarchyOverlaps    = $hierCount
}

$summary | Format-Table -AutoSize | Out-String | Write-Host

# Baseline candidates + DDP visibility
Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "BASELINE CANDIDATES" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

# Default Domain Policy visibility
$ddpName = "Default Domain Policy"
$ddpMatched = ($matchRecords | Where-Object { $_.GpoName -eq $ddpName }).Count -gt 0

$broadApplyPatterns = @(
    "Authenticated Users",
    "Domain Computers",
    "Domain Controllers",
    "Enterprise Domain Controllers"
)

function Test-BroadApply {
    param([string]$SecurityFilteringApply)

    if ([string]::IsNullOrWhiteSpace($SecurityFilteringApply)) { return $false }

    foreach ($p in $broadApplyPatterns) {
        if ($SecurityFilteringApply -match [regex]::Escape($p)) { return $true }
    }
    return $false
}

$gpoCoverage = $matchRecords |
    Where-Object { $_.GpoName } |
    Where-Object { $_.LinkEnabled -ne $false } |
    Group-Object GpoName |
    ForEach-Object {

        $gpoName = $_.Name
        $rows = $_.Group

        $uniqueScopes = ($rows | Where-Object { $_.ScopeDN } | Select-Object -ExpandProperty ScopeDN -Unique)
        $scopeCount   = $uniqueScopes.Count

        $hasDomainLink = ($rows | Where-Object { $_.ScopeType -eq "Domain" }).Count -gt 0

        $sec = ($rows | Select-Object -ExpandProperty SecurityFilteringApply -Unique | Where-Object { $_ }) -join " | "

        $looksBroad   = Test-BroadApply -SecurityFilteringApply $sec
        $enforcedCount = ($rows | Where-Object { $_.LinkEnforced -eq $true }).Count

        $scopeScore    = $scopeCount * 2
        $broadScore    = if ($looksBroad) { 10 } else { -10 }
        $domainScore   = if ($hasDomainLink -and $looksBroad) { 8 } elseif ($hasDomainLink) { -3 } else { 0 }
        $enforcedScore = [Math]::Min($enforcedCount, 3)

        $totalScore = $scopeScore + $broadScore + $domainScore + $enforcedScore

        [PSCustomObject]@{
            GpoName         = $gpoName
            TotalScore      = $totalScore
            ScopeScore      = $scopeScore
            BroadApplyScore = $broadScore
            DomainLinkScore = $domainScore
            EnforcedScore   = $enforcedScore
            LinkedScopes    = $scopeCount
            HasDomainLink   = $hasDomainLink
            LooksBroadApply = $looksBroad
            EnforcedLinks   = $enforcedCount
            SecurityFiltering = $sec
        }
    } |
    Sort-Object -Property @{ Expression = "TotalScore"; Descending = $true }

Write-Host ""
Write-Host "Default Domain Policy visibility:" -ForegroundColor Cyan
Write-Host ("  Matched search string: {0}" -f $(if ($ddpMatched) { "Yes" } else { "No" }))

if ($ddpMatched) {
    $ddpRow = $gpoCoverage | Where-Object { $_.GpoName -eq $ddpName } | Select-Object -First 1

    if ($ddpRow) {
        Write-Host "  Default Domain Policy score:" -ForegroundColor Cyan
        $ddpRow | Select-Object GpoName, TotalScore, LinkedScopes, HasDomainLink, LooksBroadApply, EnforcedLinks |
            Format-Table -AutoSize | Out-String | Write-Host
    }
    else {
        Write-Host "  Default Domain Policy score: Unable to calculate - no enabled links were included in scoring." -ForegroundColor Yellow
    }

    Write-Host "  Best practice note:" -ForegroundColor Yellow
    Write-Host "   - The Default Domain Policy is typically kept minimal (password, account lockout, Kerberos policy)." -ForegroundColor Yellow
    Write-Host "   - Broader security hardening settings are usually placed in separate baseline GPOs for clarity and safer recovery." -ForegroundColor Yellow
}

if ($gpoCoverage -and $gpoCoverage.Count -gt 0) {

    Write-Host ""
    Write-Host "Top Baseline Candidates (Top 3 by score):" -ForegroundColor Cyan

    $top3 = $gpoCoverage | Select-Object -First 3

    $top3 |
        Select-Object GpoName, TotalScore, LinkedScopes, HasDomainLink, LooksBroadApply, EnforcedLinks |
        Format-Table -AutoSize | Out-String | Write-Host

    Write-Host ""
    Write-Host "Score breakdown for Top 3:" -ForegroundColor Cyan

    foreach ($g in $top3) {
        Write-Host ""
        Write-Host ("GPO: {0}" -f $g.GpoName) -ForegroundColor Green
        Write-Host ("  Total Score       : {0}" -f $g.TotalScore)
        Write-Host ("   - ScopeScore      : {0}" -f $g.ScopeScore)
        Write-Host ("   - BroadApplyScore : {0}" -f $g.BroadApplyScore)
        Write-Host ("   - DomainLinkScore : {0}" -f $g.DomainLinkScore)
        Write-Host ("   - EnforcedScore   : {0}" -f $g.EnforcedScore)
        Write-Host ("  Security Filtering : {0}" -f $g.SecurityFiltering)
    }

}
else {
    Write-Host "Baseline candidate: None (no matches)" -ForegroundColor Yellow
}
