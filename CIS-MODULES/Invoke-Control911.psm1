function Invoke-Control911 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.1.1: Status of the Windows Firewall: Firewall state (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.1.1: Firewall state (Domain)"
        try {
            Set-NetFirewallProfile -Profile Domain -Enabled True
            $cmdOutput = "Enabled Windows Firewall for the Domain profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.1.1: $_"
}
}
