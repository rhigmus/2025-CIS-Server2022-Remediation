function Invoke-Control1526 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1526: Status of the Windows Firewall: Log File Size (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1526"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1526"
        try {
            Set-NetFirewallProfile -Profile Domain -LogFileSizeKilobytes 16384
            $cmdOutput = "Set Domain Firewall Log File Size to 16384 KB"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1526: $_"
}
}
