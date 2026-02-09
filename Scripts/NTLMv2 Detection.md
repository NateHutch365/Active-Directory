# NTLMv2 Detection Script (Event ID 4624)

This script analyses an exported Windows Security event log (`.evtx`) and extracts **authenticated NTLMv2 logon events** using structured XML parsing rather than free-text message inspection.

It is designed to give a **reliable, analysis-ready dataset** showing which accounts and systems are still using NTLMv2, supporting NTLM reduction, Kerberos migration, or authentication hardening exercises.

---

## What the Script Does

At a high level, the script:

* Loads an exported Security event log (`.evtx`)
* Iterates through **Event ID 4624** logon events
* Parses the event **XML** to reliably extract authentication fields
* Identifies logons where:

  * `AuthenticationPackageName = NTLM`
  * `LmPackageName = NTLM V2`
* Extracts the **actual logged-on identity** ("New Logon" / `Target*` fields)
* Excludes `ANONYMOUS LOGON` events
* Outputs a structured CSV containing identity, source, and logon context

Unlike message-based parsing, this approach avoids ambiguity between **Subject** and **Target** accounts and ensures the correct account is reported.

---

## Prerequisites

* PowerShell on a Windows system
* An exported Security event log (`.evtx`), typically from a domain controller
* Audit policies enabled so that Event ID 4624 includes NTLM authentication details

---

## Script

```powershell
$path = "C:\Temp\NTLM-Logs.evtx"

function Get-EventDataValue {
    param(
        [xml]$Xml,
        [string]$Name
    )
    ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
}

Get-WinEvent -Path $path |
ForEach-Object {
    $xml = [xml]$_.ToXml()

    $authPkg = Get-EventDataValue -Xml $xml -Name "AuthenticationPackageName"
    $lmPkg   = Get-EventDataValue -Xml $xml -Name "LmPackageName"

    # Only keep NTLMv2
    if ($authPkg -ne "NTLM" -or $lmPkg -ne "NTLM V2") { return }

    # "Target*" fields represent the account that actually logged on
    $targetSid  = Get-EventDataValue -Xml $xml -Name "TargetUserSid"
    $targetUser = Get-EventDataValue -Xml $xml -Name "TargetUserName"
    $targetDom  = Get-EventDataValue -Xml $xml -Name "TargetDomainName"

    # Exclude anonymous logons
    if ($targetUser -eq "ANONYMOUS LOGON") { return }

    [PSCustomObject]@{
        Time             = $_.TimeCreated
        TargetSecurityID = $targetSid
        TargetAccount    = if ($targetDom) { "$targetDom\\$targetUser" } else { $targetUser }
        Workstation      = Get-EventDataValue -Xml $xml -Name "WorkstationName"
        SourceIP         = Get-EventDataValue -Xml $xml -Name "IpAddress"
        LogonType        = Get-EventDataValue -Xml $xml -Name "LogonType"
        LmPackageName    = $lmPkg
    }
} |
Export-Csv "C:\TS-Temp\NTLMv2-Export2.csv" -NoTypeInformation -Encoding UTF8
```

---

## Output

The script produces a CSV file with the following columns:

| Column           | Description                                     |
| ---------------- | ----------------------------------------------- |
| Time             | Timestamp of the logon event                    |
| TargetSecurityID | SID of the account that authenticated           |
| TargetAccount    | Domain\Username of the authenticated account    |
| Workstation      | Source workstation name                         |
| SourceIP         | Source network address                          |
| LogonType        | Logon type (e.g. Network, Interactive, Service) |
| LmPackageName    | NTLM package version (NTLM V2)                  |

This format is suitable for further analysis, grouping, or reporting.

---

## How to Use the Script

1. Export the Security event log from the relevant server or domain controller
2. Update the `$path` variable to point to the exported `.evtx` file
3. Run the script in PowerShell
4. Review the generated CSV file at:

   ```
   C:\TS-Temp\NTLMv2-Export2.csv
   ```
5. Use the data to identify:

   * Systems frequently using NTLMv2
   * Service or user accounts relying on NTLM
   * Candidates for Kerberos migration or application remediation

---

## Interpreting the Results

* **High volumes from specific servers or appliances** often indicate legacy integrations
* **Service accounts** may require application reconfiguration or SPN/Kerberos enablement
* **Client workstation usage** may point to legacy protocols, hard-coded connections, or fallback behaviour

NTLMv2 is significantly stronger than NTLMv1, but Microsoft guidance still recommends reducing NTLM usage wherever possible in favour of Kerberos or modern authentication.

---

## Notes and Limitations

* Results only reflect the **time window** covered by the exported logs
* NTLM authentication that does not reach a domain controller may not appear
* This script is intended for **assessment and analysis**, not continuous monitoring

For ongoing visibility, consider Defender XDR Advanced Hunting or Microsoft Sentinel.
