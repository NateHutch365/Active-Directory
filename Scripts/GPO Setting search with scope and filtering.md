```powershell
# By Khalid Abulhani and Ian Matthews of www.URTech.ca - Nov 2024
# Updated by Nate Hutchinson Feb 2026: Link scope(s) + Security Filtering (Apply) + WMI filter (if set)

# Text String to Search For
$string = "NTLMv2"

# Domain
$DomainName = $env:USERDNSDOMAIN

Import-Module GroupPolicy
Import-Module ActiveDirectory

function Decode-LinkOptions {
    param([int]$Option)
    # Common mapping:
    # bit 0 (1) = link disabled when set
    # bit 1 (2) = enforced when set
    $enabled  = ($Option -band 1) -eq 0
    $enforced = ($Option -band 2) -ne 0
    [PSCustomObject]@{ Enabled = $enabled; Enforced = $enforced }
}

function Get-GpoLinkScopes {
    param(
        [Parameter(Mandatory)]
        [Guid]$GpoGuid
    )

    $guidText = $GpoGuid.ToString("B") # {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}

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
        # Extract link option for this GPO from the gPLink string:
        # [LDAP://cn={GUID},cn=policies,cn=system,...;0]
        $m = [regex]::Match($t.gPLink, "\[LDAP://[^]]*cn=$([regex]::Escape($guidText))[^;]*;(\d+)\]")
        $opt = if ($m.Success) { [int]$m.Groups[1].Value } else { $null }
        $decoded = if ($null -ne $opt) { Decode-LinkOptions -Option $opt } else { $null }

        $scopeType =
            switch ($t.ObjectClass) {
                "domainDNS"          { "Domain" }
                "organizationalUnit" { "OU" }
                "site"               { "Site" }
                default              { $t.ObjectClass }
            }

        $scopeName =
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
            ScopeName    = $scopeName
            LinkEnabled  = if ($decoded) { $decoded.Enabled } else { $null }
            LinkEnforced = if ($decoded) { $decoded.Enforced } else { $null }
        }
    }
}

function Get-GpoSecurityFiltering {
    param(
        [Parameter(Mandatory)]
        [Guid]$GpoGuid,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    # Security Filtering in GPMC terms = principals with "Apply group policy"
    # This surfaces only the Apply list (not every ACL entry).
    $perms = Get-GPPermission -Guid $GpoGuid -Domain $Domain -All -ErrorAction Stop

    $apply = $perms | Where-Object { $_.Permission -eq "GpoApply" }

    # Return friendly strings like "DOMAIN\Group"
    $apply | ForEach-Object {
        $trustee = $_.Trustee
        if ($trustee.Domain -and $trustee.Name) { "$($trustee.Domain)\$($trustee.Name)" }
        elseif ($trustee.Name) { $trustee.Name }
        else { "[Unknown Trustee]" }
    } | Sort-Object -Unique
}

Write-Host "Finding all the GPOs in $DomainName"
$allGposInDomain = Get-GPO -All -Domain $DomainName
$sortedGpos = $allGposInDomain | Sort-Object DisplayName

Write-Host "Starting search..."
$counter = 1

foreach ($gpo in $sortedGpos) {

    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    if ($report -match $string) {

        Write-Host "********** Match found in: $counter. $($gpo.DisplayName) **********" -ForegroundColor Green

        # --- Linked scopes ---
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

        # --- Security filtering (Apply Group Policy) ---
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

        # --- WMI filter (if present) ---
        # Get-GPO exposes WmiFilter in many environments; if null, it's not set.
        $wmi = (Get-GPO -Guid $gpo.Id -Domain $DomainName).WmiFilter
        if ($wmi) {
            Write-Host "  WMI filter: $($wmi.Name)"
        }
        else {
            Write-Host "  WMI filter: (None)"
        }

        Write-Host ""  # spacer
    }
    else {
        Write-Host "$counter. No match in: $($gpo.DisplayName)"
    }

    $counter++
}
```
