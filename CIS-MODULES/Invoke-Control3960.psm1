function Invoke-Control3960 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3960: Status of the Windows Firewall: Apply local firewall rules (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3960"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3960: Apply local firewall rules (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -AllowLocalRules False
            $cmdOutput = "Disabled local firewall rules for Public profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3960: $_"
}
