function Invoke-Control8160 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8160: Status of the Windows Firewall: Log File Size (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8160"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8160: Firewall log file size (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384
            $cmdOutput = "Set Private profile firewall log file size to 16384 KB (16 MB)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8160: $_"
}
