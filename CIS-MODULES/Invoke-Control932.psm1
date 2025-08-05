function Invoke-Control932 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.3.2: Status of the Windows Firewall: Inbound connections (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.3.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.3.2: Inbound firewall (Public) setting"
        try {
            Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
            $cmdOutput = "Set Windows Firewall (Public) to block inbound connections by default."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.3.2: $_"
}
}
