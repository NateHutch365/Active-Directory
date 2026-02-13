# GpoLens

**GpoLens** is a PowerShell-based analysis tool designed to inspect how a specific configuration setting is implemented across Group Policy Objects (GPOs) in an Active Directory domain.

The original idea for this tool came from a PowerShell script created by Khalid Abulhani and Ian Matthews: https://www.urtech.ca/2024/11/solved-powershell-script-to-search-all-gpos-for-a-setting/

It goes beyond simple string matching and provides:

* GPO discovery by setting content
* Linked scope analysis (Domain / OU / Site)
* Security filtering visibility
* WMI filter visibility
* Same-scope overlap detection
* Hierarchy overlap detection (parent/child OU relationships)
* Baseline candidate scoring (Top 3 ranked suggestions)
* Optional CSV export for reporting and review

GpoLens is intended for architectural review, security hardening validation, and GPO hygiene exercises.

---

# What Problem GpoLens Solves

In many environments, the same setting is configured in multiple GPOs across different scopes. This can result in:

* Redundant configuration
* Policy conflicts
* Hidden overrides
* Drift over time
* Difficulty identifying the "true" baseline policy

GpoLens helps answer:

* Where is this setting configured?
* Where is it linked?
* Are multiple GPOs configuring it at the same scope?
* Is there parent/child scope overlap?
* Which GPO most likely represents the intended baseline?

---

# Requirements

* Windows PowerShell 5.1 (tested in PowerShell ISE)
* GroupPolicy module
* ActiveDirectory module
* Domain read permissions sufficient to enumerate GPOs and linked scopes

Run on:

* Domain Controller (recommended), or
* Management workstation with RSAT and sufficient permissions

---

# Supported Parameters

```powershell
param(
    [string]$SearchString = "NTLMv2",
    [switch]$ShowOverlaps,
    [switch]$ExportCsv,
    [string]$ExportPath = "C:\TS-Temp"
)
```

## -SearchString

The text string to search for within each GPO’s XML report.

Example:

```powershell
-SearchString "NTLMv2"
-SearchString "LAN Manager authentication level"
-SearchString "SMB signing"
```

---

## -ShowOverlaps

Enables additional overlap analysis:

### Same-Scope Overlap

Detects multiple matching GPOs linked to the same container or site.

Example:

* Two GPOs linked to `OU=Servers` both configure the same setting.

### Hierarchy Overlap

Detects when matching GPOs are linked at both:

* A parent container (e.g., Domain root)
* A child OU beneath it

This highlights architectural complexity and potential override risk.

---

## -ExportCsv

Exports analysis results to CSV files.

When enabled, GpoLens generates:

* `GpoMatches.csv`
* `SameScopeOverlaps.csv` (if applicable)
* `HierarchyOverlaps.csv` (if applicable)

---

## -ExportPath

Specifies the folder for CSV export.

Default:

```powershell
C:\TS-Temp
```

---

# Output Sections Explained

## 1. Match Discovery

For each GPO containing the search string:

* Linked scopes are listed
* Link enabled/enforced state shown
* Security filtering (Apply Group Policy) displayed
* WMI filter shown (if present)

---

## 2. Overlap Analysis (Optional)

### Same-Scope Overlap

Multiple GPOs linked to the same scope configuring the same setting.

Risk:

* Redundancy
* Conflicting edits in future
* Unclear ownership

---

### Hierarchy Overlap

Matching GPOs linked at parent and child levels.

Risk:

* Override complexity
* Enforced link confusion
* Hidden inheritance effects

Note: This is structural analysis only. It does not calculate effective RSOP.

---

## 3. Summary Table

Provides a quick overview:

* Total matching GPOs
* Unique linked scopes
* Same-scope overlaps
* Hierarchy overlaps

Includes a high-level recommendation message.

---

# Baseline Candidate Logic

GpoLens ranks matching GPOs using a heuristic scoring model to suggest likely baseline candidates.

The goal is to identify the GPO most likely intended as the primary configuration baseline.

## Scoring Components

### 1. Scope Breadth (LinkedScopes × 2)

More enabled links = broader intended coverage.

### 2. Broad Security Filtering (+10 / -10)

If Apply Group Policy includes broad principals such as:

* Authenticated Users
* Domain Computers
* Domain Controllers
* Enterprise Domain Controllers

Then it receives a strong positive score.

If security filtering appears narrow, it receives a penalty.

### 3. Domain Link Bonus

If linked at Domain level AND broadly applied:

+8 bonus

If linked at Domain level but narrowly filtered:

-3 penalty

### 4. Enforced Links (capped at +3)

Small bonus for enforced links, but not dominant.

---

## Top 3 Candidate Output

Instead of selecting a single GPO silently, GpoLens displays:

* Top 3 GPOs by total score
* Score breakdown:

  * ScopeScore
  * BroadApplyScore
  * DomainLinkScore
  * EnforcedScore

This allows transparent architectural review.

Important:

This is a heuristic, not an RSOP calculation.
It suggests design intent, not guaranteed effective outcome.

---

# Example Usage

Basic search:

```powershell
.\GpoLens.ps1 -SearchString "NTLMv2"
```

With overlap analysis:

```powershell
.\GpoLens.ps1 -SearchString "NTLMv2" -ShowOverlaps
```

With CSV export:

```powershell
.\GpoLens.ps1 -SearchString "NTLMv2" -ShowOverlaps -ExportCsv
```

With CSV export and custom output path:

```powershell
.\GpoLens.ps1 -SearchString "NTLMv2" -ShowOverlaps -ExportCsv -ExportPath "C:\Reports\GpoLens"
```

---

# Intended Use Cases

* NTLM reduction reviews
* Security baseline consolidation
* Hardening validation
* Pre-migration architecture clean-up
* Change control review evidence
* Identifying redundant GPOs

---

# Limitations

* Does not compute effective policy (no RSOP)
* Does not account for block inheritance or link order precedence
* Does not evaluate item-level targeting
* Assumes read access to GPOs and linked containers

GpoLens is designed for architectural visibility, not runtime policy simulation.

## 🔎 Search Behaviour and XML Encoding Notes

GpoLens searches the **raw XML output** of each GPO report. This means searches are performed against the exact text stored in the XML — not the friendly formatting you see in the Group Policy Management Console.

### Why longer search strings sometimes return no results

Some policy values contain special characters (for example `&`, `<`, `>`). In XML, these characters are encoded for safety:

| Character | XML Representation |
| --------- | ------------------ |
| `&`       | `&amp;`            |
| `<`       | `&lt;`             |
| `>`       | `&gt;`             |

For example, this setting:

```
Send NTLMv2 response only. Refuse LM & NTLM
```

Is stored in the XML as:

```
Send NTLMv2 response only. Refuse LM &amp; NTLM
```

If you search for:

```
"Send NTLMv2 response only. Refuse LM & NTLM"
```

It may not match unless the script normalises the XML encoding.

---

### ✅ Recommended search patterns

To ensure reliable matching, prefer one of the following:

* `Send NTLMv2 response only`
* `Refuse LM`
* `LmCompatibilityLevel`
* `Network security: LAN Manager authentication level`
* `NTLM V2`

These are more resilient to encoding differences and formatting variations.

---

### 🔬 Example

Instead of this (may fail due to XML encoding):

```
-SearchString "Send NTLMv2 response only. Refuse LM & NTLM"
```

Use one of these:

```
-SearchString "Send NTLMv2 response only"
```

or

```
-SearchString "LmCompatibilityLevel"
```

---

### 📌 Important

GpoLens performs **literal text matching** against the XML report. It does not interpret policy values or calculate effective settings. If a string does not appear in the XML exactly (or after encoding normalisation), it will not be detected.

When troubleshooting unexpected results, manually inspect the GPO XML using:

```powershell
Get-GPOReport -Name "Default Domain Policy" -ReportType Xml
```

Then search within that output to determine the exact string representation stored in the report.


---

# Versioning Recommendation

Suggested version label for current feature set:

**GpoLens v1.0 – Architecture & Baseline Analyzer**

Future enhancements could include:

* RSOP sampling
* Conflict value comparison
* Confidence scoring
* HTML reporting mode
* Interactive filtering

---

# Closing Notes

GpoLens is most effective when used as part of a structured AD hygiene or security review process.

It is intentionally transparent in its scoring model so that architectural decisions remain human-led and defensible.

Always validate baseline suggestions against design intent and documented policy standards.
