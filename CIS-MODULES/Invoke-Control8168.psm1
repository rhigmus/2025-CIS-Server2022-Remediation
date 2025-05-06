function Invoke-Control8168 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8168: Status of the Windows Firewall: Log File Size (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8168"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8168: Firewall log size (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
            $cmdOutput = "Set firewall log file size for Public profile to 16384 KB (16 MB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8168: $_"
}
}
