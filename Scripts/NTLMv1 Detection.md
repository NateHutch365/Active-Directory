# NTLMv1 Detection Script (Event ID 4624)

This script analyses an exported Windows Security event log (`.evtx`) that has already been filtered to **Event ID 4624 (successful logons)** and checks for **authenticated NTLMv1 usage**, excluding known **ANONYMOUS LOGON** noise.

It is intended to support NTLM reduction or deprecation work, particularly when validating whether NTLMv1 is still in use before enforcement.

---

## What the Script Does

At a high level, the script performs the following actions:

* Loads an exported `.evtx` file containing Security log events
* Iterates through each event and displays a progress bar while processing
* Identifies logon events where:

  * The authentication package is NTLM
  * The NTLM package version is **NTLM V1**
  * The logon is **not** associated with `ANONYMOUS LOGON`
* Collects any matching NTLMv1 events
* Outputs:

  * **"No NTLMv1 found"** if no authenticated NTLMv1 usage is detected
  * Otherwise, a readable table showing the matching events

This aligns with Microsoft guidance that anonymous NTLMv1 events do not represent real NTLMv1 session usage and can be ignored.

---

## Prerequisites

* A Windows system with PowerShell
* An exported Security event log (`.evtx`) from a domain controller or relevant server
* The log should already be filtered to **Event ID 4624** to improve performance

---

## Script

```powershell
$path = "C:\Temp\NTLM-Logs.evtx"

# Load events first so we can show progress accurately
$events = Get-WinEvent -Path $path
$total  = $events.Count

$results = New-Object System.Collections.Generic.List[object]

for ($i = 0; $i -lt $total; $i++) {
    $evt = $events[$i]

    # Progress
    $pct = [int](($i + 1) / $total * 100)
    Write-Progress -Activity "Scanning 4624 events for NTLMv1" `
                   -Status "$($i + 1) of $total ($pct%)" `
                   -PercentComplete $pct

    $msg = $evt.Message

    # Filter: NTLMv1 and NOT anonymous
    if ($msg -match "Package Name \(NTLM only\):\s+NTLM V1" -and
        $msg -notmatch "Account Name:\s+ANONYMOUS LOGON" -and
        $msg -notmatch "Security ID:\s+ANONYMOUS LOGON") {
        $results.Add($evt)
    }
}

# Clear progress bar
Write-Progress -Activity "Scanning 4624 events for NTLMv1" -Completed

if ($results.Count -eq 0) {
    Write-Host "No NTLMv1 found"
}
else {
    $results | Select-Object TimeCreated, Id, MachineName, Message
}
```

---

## How to Use the Script

1. Export the Security event log from a domain controller

   * Ensure it includes **Event ID 4624**
2. Update the `$path` variable to point to your `.evtx` file
3. Run the script in PowerShell
4. Observe the progress bar while the log is processed
5. Review the output:

   * If you see **"No NTLMv1 found"**, no authenticated NTLMv1 usage was detected in the log window
   * If events are returned, investigate the `Message` field to identify the source systems and accounts

---

## Interpreting the Results

* **No NTLMv1 found**

  * Indicates no evidence of authenticated NTLMv1 usage in the captured logs
  * Typically supports moving forward with **NTLMv1 enforcement/denial**, subject to monitoring and change control

* **NTLMv1 events returned**

  * Indicates legacy systems, applications, or services still using NTLMv1
  * These should be remediated before disabling NTLMv1

Anonymous NTLMv1 events are intentionally excluded, as Microsoft documents that these do not represent real NTLMv1 session security usage.

---

## Notes and Limitations

* Findings are only valid for the **time window covered by the exported logs**
* NTLM between non-DC systems may not always surface in DC logs
* This script is intended for **assessment and evidence gathering**, not continuous monitoring

For long-term monitoring, consider using Defender XDR Advanced Hunting or Microsoft Sentinel.
