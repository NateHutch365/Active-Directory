## PowerShell script to export AD user password last set information to a CSV file
Get-ADUser -SearchBase "OU=Finance,OU=CorpUsers,DC=ad,DC=contoso,DC=com" -Filter * -Properties PwdLastSet, PasswordExpired | 
    Sort-Object Name | 
    Select-Object Name, SamAccountName, Enabled, 
        @{Name='PwdLastSet'; Expression={[DateTime]::FromFileTime($_.PwdLastSet)}}, 
        PasswordExpired | 
    Export-Csv -Path "C:\Reports\AD_PasswordLastSet.csv" -NoTypeInformation