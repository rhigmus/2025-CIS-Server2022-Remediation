function Invoke-Control937 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.3.7: Status of the Windows Firewall: Log File Size (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.3.7"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.3.7: Firewall log size (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
            $cmdOutput = "Set firewall log file size for Public profile to 16384 KB (16 MB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.3.7: $_"
}
}
