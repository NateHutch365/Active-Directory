# Used to determine the NetBIOS settings for the local NIC
# If WINS servers are configured this is a strong indicator that NetBIOS and legacy protocols may still be in use
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" |
Select-Object Description,
@{n='IPv4';e={ ($_.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join ', ' }},
@{n='NetBIOS';e={
    switch ($_.TcpipNetbiosOptions) {
        0 { 'Default (DHCP / node type)' }
        1 { 'Enabled' }
        2 { 'Disabled' }
        default { "Unknown ($($_.TcpipNetbiosOptions))" }
    }
}},
WINSEnableLMHostsLookup,
WINSPrimaryServer,
WINSSecondaryServer
