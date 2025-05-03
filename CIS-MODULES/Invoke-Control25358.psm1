function Invoke-Control25358 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25358: Windows - Status of NetBIOS name resolution"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25358"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25358: Windows - Status of NetBIOS name resolution"
        try {
            # Disable NetBIOS over TCP/IP
            Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" | ForEach-Object {
                $_.SetTcpipNetbios(2) | Out-Null
    
            $cmdOutput = "Disabled NetBIOS over TCP/IP for all active network adapters."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25358: $_"
}
