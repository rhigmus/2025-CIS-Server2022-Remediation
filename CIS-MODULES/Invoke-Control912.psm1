function Invoke-Control912 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.1.2: Status of the Windows Firewall: Inbound connections (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.1.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.1.2: Status of the Windows Firewall: Inbound connections (Domain) setting"
        try {
            # Set Windows Firewall inbound connections to block by default for Domain profile
            Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
            $cmdOutput = "Set DefaultInboundAction to Block for Domain firewall profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.1.2: $_"
}
}
