```powershell
# By Khalid Abulhani and Ian Matthews of www.URTech.ca - Nov 2024
# Text String to Search For - Update string parameter to required setting you are looking for in the GPO's
$string = "Biometrics"
# Which Domain Are You On
$DomainName = $env:USERDNSDOMAIN
# Find All GPO's in this Domain
Write-Host "Finding all the GPOs in $DomainName"
Import-Module GroupPolicy
$allGposInDomain = Get-GPO -All -Domain $DomainName
# Sort GPO's Alphabetically by DisplayName
$sortedGpos = $allGposInDomain | Sort-Object DisplayName
# Look Through Each GPO's XML for the Text String and Output a Line to the Screen For Each So You Know What is Going On
Write-Host "Starting search..."
$counter = 1
foreach ($gpo in $sortedGpos) {
   $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
   if ($report -match $string) {
       Write-Host "********** Match found in: $counter. $($gpo.DisplayName) **********" -ForegroundColor Green
   } else {
       Write-Host "$counter. No match in: $($gpo.DisplayName)"
   }
   $counter++
}
```