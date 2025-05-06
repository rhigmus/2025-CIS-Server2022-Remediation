function Invoke-Control10431 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10431: Status of the Require use of specific security layer for remote (RDP) connections setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10431"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10431: Status of the Require use of specific security layer for remote (RDP) connections setting"
        try {
            # Enforce use of SSL (TLS 1.0 or higher) for RDP security layer
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -PropertyType DWord -Value 2 -Force | Out-Null
    
            $cmdOutput = "Set RDP SecurityLayer to 2 (SSL)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10431: $_"
}
}
