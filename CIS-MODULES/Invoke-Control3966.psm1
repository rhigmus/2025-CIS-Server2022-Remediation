function Invoke-Control3966 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3966: Status of the Windows Firewall: Apply local connection security rules (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3966"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3966"
        try {
            Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False
            $cmdOutput = "Disabled application of local connection security rules on Public profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3966: $_"
}
}
