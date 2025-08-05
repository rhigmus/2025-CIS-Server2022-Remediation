function Invoke-Control922 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.2.2: Status of the Windows Firewall: Inbound connections (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.2.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.2.2: Block inbound connections (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
            $cmdOutput = "Set Private profile to block all inbound connections."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.2.2: $_"
}
}
